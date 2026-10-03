package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	legacyHealthScript = "network-split-domestic-health.sh"
	healthState        = "network-split-domestic-health.state"
	healthTempPrefix   = healthState + ".tmp."
	legacyDNSState     = "network-split-dns-routes.json"
	residueGrace       = 5 * time.Minute
)

var errHealthBusy = errors.New("health state writer is active; no residue removed")

type Residue struct {
	Name     string `json:"name"`
	Bytes    int64  `json:"bytes"`
	SHA256   string `json:"sha256,omitempty"`
	Skipped  string `json:"skipped,omitempty"`
	identity os.FileInfo
}

func residueName(name string, healthOnly bool) bool {
	if !healthOnly && name == legacyDNSState {
		return true
	}
	if !strings.HasPrefix(name, healthTempPrefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, healthTempPrefix)
	pid, err := strconv.ParseUint(suffix, 10, 32)
	return err == nil && pid > 0 && strconv.FormatUint(pid, 10) == suffix
}

// Accept known state fields, including a final interrupted field. Contents are
// treated as data; neither legacy shell state nor JSON is ever executed.
func healthTemporaryData(data string) bool {
	keys := map[string]bool{"version": true, "failure_count": true, "last_refresh": true,
		"probe_interval": true, "last_probe": true, "cooldown_until": true,
		"baseline_ms": true, "slow_count": true, "probe_samples": true}
	if data == "" {
		return true
	}
	lines := strings.Split(strings.TrimSuffix(data, "\n"), "\n")
	seen := map[string]bool{}
	for index, line := range lines {
		key, value, found := strings.Cut(line, "=")
		partial := index == len(lines)-1 && !strings.HasSuffix(data, "\n")
		if !found && partial {
			for known := range keys {
				if strings.HasPrefix(known, key) && !seen[known] {
					return true
				}
			}
		}
		if !found || !keys[key] || seen[key] || (value == "" && key != "probe_samples" && !partial) {
			return false
		}
		seen[key] = true
		for _, c := range value {
			if !(c >= '0' && c <= '9' || key == "probe_samples" && c == ',') {
				return false
			}
		}
	}
	return true
}

func (d *Deployer) inspectResidue(parent *os.Root, name string) Residue {
	result := Residue{Name: name}
	info, err := parent.Lstat(name)
	if err != nil {
		result.Skipped = err.Error()
		return result
	}
	result.identity, result.Bytes = info, info.Size()
	status := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || int(status.Uid) != os.Geteuid() || status.Nlink != 1 || info.Mode().Perm() != 0o600 || info.Size() > 4096 {
		result.Skipped = "not a private, owned, bounded regular state file"
		return result
	}
	if d.Now().Sub(info.ModTime()) < residueGrace {
		result.Skipped = "state file is too recent"
		return result
	}
	file, err := parent.Open(name)
	if err != nil {
		result.Skipped = err.Error()
		return result
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		result.Skipped = "state file changed while opening"
		return result
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 || int64(len(data)) != info.Size() {
		result.Skipped = "state file changed or could not be read"
		return result
	}
	valid := healthTemporaryData(string(data))
	if name == legacyDNSState {
		value := strings.TrimSpace(string(data))
		valid = value == "{}" || value == "[]"
	}
	if !valid {
		result.Skipped = "unrecognized or nonempty legacy state; preserved for review"
		return result
	}
	digest := sha256.Sum256(data)
	result.SHA256 = hex.EncodeToString(digest[:])
	return result
}

func (d *Deployer) residues(parent *os.Root, healthOnly bool) ([]Residue, error) {
	names, err := backupDirectoryNames(parent)
	if err != nil {
		return nil, err
	}
	result := []Residue{}
	for _, name := range names {
		if residueName(name, healthOnly) {
			result = append(result, d.inspectResidue(parent, name))
		}
	}
	return result, nil
}

func (d *Deployer) Residues() ([]Residue, error) {
	parent, err := d.backupParent()
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	return d.residues(parent, false)
}

// Match zsystem flock's POSIX fcntl lock, not the proxy's BSD flock lock.
func (d *Deployer) lockHealthState() (func(), error) {
	fd, err := syscall.Open(d.HealthLock, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), d.HealthLock)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		file.Close()
		return nil, errors.New("unsafe health state lock")
	}
	lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0}
	if err := syscall.FcntlFlock(uintptr(fd), syscall.F_SETLK, &lock); err != nil {
		file.Close()
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EACCES) {
			return nil, errHealthBusy
		}
		return nil, err
	}
	return func() { file.Close() }, nil
}

func (d *Deployer) CleanupResidues(healthOnly bool) error {
	release, err := d.lockHealthState()
	if errors.Is(err, errHealthBusy) && healthOnly {
		return nil
	}
	if err != nil {
		return err
	}
	defer release()
	return d.cleanupResiduesLocked(healthOnly)
}

func (d *Deployer) cleanupResiduesLocked(healthOnly bool) error {
	parent, err := d.backupParent()
	if err != nil {
		return err
	}
	defer parent.Close()
	items, err := d.residues(parent, healthOnly)
	if err != nil {
		return err
	}
	var selected []Residue
	for _, item := range items {
		if item.Skipped == "" {
			selected = append(selected, item)
		}
	}
	if len(selected) == 0 {
		if !healthOnly {
			fmt.Fprintf(d.Out, "State residues: removed=0 remaining=%d\n", len(items))
		}
		return nil
	}
	before, err := d.maintenanceState()
	if err != nil {
		return err
	}
	checks := [][]string{}
	if !healthOnly {
		checks = append(checks, []string{"/usr/bin/pgrep", "-f", `[/]network-split-dns-route-agent`})
	}
	args := []string{"/usr/sbin/lsof", "-nP", "-t"}
	for _, item := range selected {
		args = append(args, filepath.Join(d.BackupParent, item.Name))
	}
	checks = append(checks, args)
	for _, args := range checks {
		out, err := d.Run(args...)
		code, known := exitCode(err)
		if !known || code != 1 || strings.TrimSpace(out) != "" {
			return fmt.Errorf("state may still be in use; nothing removed (%s)", args[0])
		}
	}
	for _, item := range selected {
		current := d.inspectResidue(parent, item.Name)
		if current.Skipped != "" || !os.SameFile(item.identity, current.identity) || item.SHA256 != current.SHA256 {
			return errors.New("state changed during inspection; nothing removed")
		}
	}
	if err := d.checkInterrupted(); err != nil {
		return err
	}
	removed, bytes := 0, int64(0)
	for _, item := range selected {
		if err := parent.Remove(item.Name); err != nil {
			return fmt.Errorf("state cleanup incomplete after %d removals: %w", removed, err)
		}
		removed++
		bytes += item.Bytes
	}
	remaining, err := d.residues(parent, healthOnly)
	if err != nil {
		return fmt.Errorf("state files removed; verification failed: %w", err)
	}
	after, err := d.maintenanceState()
	if err != nil || !reflect.DeepEqual(before, after) {
		return errors.New("state files removed; unchanged runtime could not be confirmed")
	}
	fmt.Fprintf(d.Out, "State residues: removed=%d bytes=%d remaining=%d; runtime unchanged\n", removed, bytes, len(remaining))
	return nil
}
