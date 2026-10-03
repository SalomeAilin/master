package deploy

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	"network-owned-engine/internal/healthcheck"
	"network-owned-engine/internal/runtimecheck"
)

const (
	legacyHealthScript = runtimecheck.LegacyHealthScript
	healthState        = "network-split-domestic-health.state"
	healthTempPrefix   = healthState + ".tmp."
	legacyDNSState     = "network-split-dns-routes.json"
	residueGrace       = 5 * time.Minute
	policyCacheName    = "network_split_policy.cpython-313.pyc"
)

var errHealthBusy = healthcheck.ErrBusy

type Residue = healthcheck.Residue

func lockState(path string) (func(), error)          { return healthcheck.LockState(path) }
func (d *Deployer) lockHealthState() (func(), error) { return lockState(d.HealthLock) }
func (d *Deployer) Residues() ([]Residue, error)     { return d.healthJob().Residues() }
func (d *Deployer) CleanupResidues(healthOnly bool) error {
	return d.healthJob().CleanupResidues(healthOnly)
}

// The digest is supplied after reviewing the one retired cache. This command
// is not a general Python-cache collector and accepts no caller-selected path.
func ValidPolicyCacheDigest(value string) bool {
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == 32
}

func inspectPolicyCache(sbin *os.Root, digest string) (directory, file os.FileInfo, size int64, resultErr error) {
	if _, err := sbin.Lstat("network_split_policy.py"); !os.IsNotExist(err) {
		return nil, nil, 0, errors.New("legacy policy source exists or cannot be checked")
	}
	directory, err := sbin.Lstat("__pycache__")
	if os.IsNotExist(err) {
		return nil, nil, 0, nil
	}
	if err != nil {
		return nil, nil, 0, err
	}
	if !directory.IsDir() || directory.Mode().Perm()&0o022 != 0 || int(directory.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		return nil, nil, 0, errors.New("unsafe policy cache directory")
	}
	cache, err := sbin.OpenRoot("__pycache__")
	if err != nil {
		return nil, nil, 0, err
	}
	defer cache.Close()
	opened, err := cache.Stat(".")
	if err != nil || !os.SameFile(directory, opened) {
		return nil, nil, 0, errors.New("policy cache directory changed while opening")
	}
	names, err := runtimecheck.DirectoryNames(cache)
	if err != nil {
		return nil, nil, 0, err
	}
	if len(names) == 0 {
		return directory, nil, 0, nil
	}
	if len(names) != 1 || names[0] != policyCacheName {
		return nil, nil, 0, errors.New("cache contains unreviewed entries; nothing removed")
	}
	file, err = cache.Lstat(policyCacheName)
	if err != nil {
		return nil, nil, 0, err
	}
	stat := file.Sys().(*syscall.Stat_t)
	if !file.Mode().IsRegular() || file.Mode().Perm()&0o022 != 0 || int(stat.Uid) != os.Geteuid() || stat.Nlink != 1 || file.Size() > 64<<10 {
		return nil, nil, 0, errors.New("unsafe or oversized policy cache file")
	}
	input, err := cache.Open(policyCacheName)
	if err != nil {
		return nil, nil, 0, err
	}
	defer input.Close()
	opened, err = input.Stat()
	if err != nil || !os.SameFile(file, opened) {
		return nil, nil, 0, errors.New("policy cache changed while opening")
	}
	actual, size, err := hashFile(input)
	if err != nil || actual != strings.ToLower(digest) {
		return nil, nil, 0, errors.New("policy cache does not match the reviewed SHA-256")
	}
	return directory, file, size, nil
}

// CleanupPolicyCache runs under the existing deployment lock, removes only the
// reviewed bytecode, then uses nonrecursive removal for its empty directory.
func (d *Deployer) CleanupPolicyCache(digest string) error {
	if !ValidPolicyCacheDigest(digest) {
		return errors.New("supply the reviewed cache's 64-digit SHA-256")
	}
	sbinPath := filepath.Dir(d.Tool)
	sbin, err := runtimecheck.OpenRoot(sbinPath)
	if err != nil {
		return err
	}
	defer sbin.Close()
	directory, file, bytes, err := inspectPolicyCache(sbin, digest)
	if err != nil {
		return err
	}
	if directory == nil {
		fmt.Fprintln(d.Out, "Retired policy cache already absent; nothing changed")
		return nil
	}
	before, err := d.maintenanceState()
	if err != nil {
		return err
	}
	target := filepath.Join(sbinPath, "__pycache__")
	if file != nil {
		target = filepath.Join(target, policyCacheName)
	}
	for _, args := range [][]string{{"/usr/bin/pgrep", "-f", `[/]network_split_policy[.]py`}, {"/usr/sbin/lsof", "-nP", "-t", target}} {
		out, err := d.Run(args...)
		code, known := exitCode(err)
		if !known || code != 1 || strings.TrimSpace(out) != "" {
			return errors.New("legacy policy or cache may be in use; nothing removed")
		}
	}
	ready, err := d.maintenanceState()
	if err != nil || !reflect.DeepEqual(before, ready) {
		return errors.New("runtime changed during cache inspection; nothing removed")
	}
	currentDir, currentFile, _, err := inspectPolicyCache(sbin, digest)
	if err != nil || currentDir == nil || !os.SameFile(directory, currentDir) ||
		(file == nil) != (currentFile == nil) || file != nil && !os.SameFile(file, currentFile) {
		return errors.New("policy cache changed during inspection; nothing removed")
	}
	if err := d.checkInterrupted(); err != nil {
		return err
	}
	files := 0
	if file != nil {
		if err := sbin.Remove(filepath.Join("__pycache__", policyCacheName)); err != nil {
			return err
		}
		files = 1
	}
	if err := sbin.Remove("__pycache__"); err != nil {
		return fmt.Errorf("removed %d reviewed cache file(s); directory preserved: %w", files, err)
	}
	if _, err := sbin.Lstat("__pycache__"); !os.IsNotExist(err) {
		return errors.New("cache removal completed, but absence could not be verified")
	}
	after, err := d.maintenanceState()
	if err != nil || !reflect.DeepEqual(before, after) {
		return errors.New("cache removed, but unchanged runtime could not be confirmed")
	}
	fmt.Fprintf(d.Out, "Retired policy cache removed: files=%d bytes=%d; empty directory removed; runtime unchanged\n", files, bytes)
	return nil
}
