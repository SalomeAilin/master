package deploy

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"network-owned-engine/internal/healthcheck"
)

func launchValues(details string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(details, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " = ")
		if _, exists := values[key]; ok && !exists {
			values[key] = value
		}
	}
	return values
}

func (d *Deployer) healthDefinition() string {
	return filepath.Join(filepath.Dir(d.Plist), healthPlistName)
}

func (d *Deployer) validateHealthDefinition(source string) error {
	candidate, err := d.readPlist(source)
	if err != nil {
		return err
	}
	previous, err := d.readPlist(d.healthDefinition())
	if err != nil {
		return err
	}
	if candidate["Label"] != strings.TrimPrefix(healthLabel, "system/") || candidate["RunAtLoad"] != true ||
		candidate["StartInterval"] != float64(30) || !reflect.DeepEqual(candidate["ProgramArguments"], []any{d.Tool, "health-check"}) {
		return errors.New("unexpected native health service definition")
	}
	a, b := maps.Clone(previous), maps.Clone(candidate)
	delete(a, "ProgramArguments")
	delete(b, "ProgramArguments")
	if !reflect.DeepEqual(a, b) {
		return errors.New("health settings other than program arguments would change")
	}
	return nil
}

func (d *Deployer) stopHealthJob() (bool, error) {
	details, err := d.Run("/bin/launchctl", "print", healthLabel)
	if code, known := exitCode(err); known && code == 113 {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	pid := 0
	if raw := launchValues(details)["pid"]; raw != "" {
		pid, err = strconv.Atoi(raw)
		if err != nil || pid < 1 {
			return false, errors.New("invalid health job PID")
		}
	}
	if _, err := d.Run("/bin/launchctl", "bootout", healthLabel); err != nil {
		return false, err
	}
	for attempt := 0; pid > 0 && attempt < 150; attempt++ {
		alive, err := d.ProcessAlive(pid)
		if err != nil {
			return true, err
		}
		if !alive {
			return true, nil
		}
		d.Sleep(100 * time.Millisecond)
	}
	if pid > 0 {
		return true, errors.New("health job has not exited")
	}
	return true, nil
}

func (d *Deployer) startHealthJob() error {
	for attempt := 0; attempt < 10; attempt++ {
		_, err := d.Run("/bin/launchctl", "bootstrap", "system", d.healthDefinition())
		code, known := exitCode(err)
		if err == nil || !known || code != 5 || attempt == 9 {
			return err
		}
		d.Sleep(500 * time.Millisecond)
	}
	return errors.New("could not start health job")
}

func (d *Deployer) waitNativeHealth() error {
	for attempt := 0; attempt < 150; attempt++ {
		details, err := d.Run("/bin/launchctl", "print", healthLabel)
		if err == nil {
			values := launchValues(details)
			if values["program"] != d.Tool {
				return errors.New("health job is not using the Go tool")
			}
			runs, _ := strconv.Atoi(values["runs"])
			if code := values["last exit code"]; code != "" && values["state"] == "not running" && runs > 0 {
				if code != "0" {
					return fmt.Errorf("native health job failed: exit %s", code)
				}
				return nil
			}
		}
		if err := d.checkInterrupted(); err != nil {
			return err
		}
		d.Sleep(100 * time.Millisecond)
	}
	return errors.New("native health job did not complete its first run")
}

func (d *Deployer) previousHealthProbe() int64 {
	state, err := healthcheck.Read(filepath.Join(d.BackupParent, healthState), d.Now().Unix())
	if err != nil {
		return 0
	}
	return state.LastProbe
}

func (d *Deployer) acceptHealthSample(previous int64) error {
	if d.AcceptHealth != nil {
		return d.AcceptHealth(previous)
	}
	for attempt := 0; attempt < 31; attempt++ {
		state, err := healthcheck.Read(filepath.Join(d.BackupParent, healthState), d.Now().Unix())
		if err == nil {
			if state.LastProbe > 0 && state.LastProbe != previous && state.Failures == 0 {
				fmt.Fprintf(d.Out, "Scheduled native health probe accepted: last_probe=%d failures=0\n", state.LastProbe)
				return nil
			}
		}
		if err := d.checkInterrupted(); err != nil {
			return err
		}
		if attempt < 30 {
			d.Sleep(5 * time.Second)
		}
	}
	return errors.New("native scheduled health probe was not accepted within 150 seconds")
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest, _, err := hashFile(file)
	return digest, err
}

// InstallHealthMaintenance changes only the maintenance tool and the existing
// health job. The prior files are kept privately until native activation passes.
func (d *Deployer) InstallHealthMaintenance() (resultErr error) {
	definition := d.healthDefinition()
	sourceDefinition := filepath.Join(d.Root, healthPlistName)
	if err := d.validateHealthDefinition(sourceDefinition); err != nil {
		return err
	}
	if _, err := d.Run("/bin/launchctl", "print", healthLabel); err != nil {
		return err
	}
	if err := d.preflightHealth(); err != nil {
		return err
	}
	if _, err := d.Backups(); err != nil {
		return err
	}
	before, err := d.maintenanceState()
	if err != nil {
		return err
	}
	toolHash, err := fileDigest(filepath.Join(d.Root, ToolName))
	if err != nil {
		return err
	}
	plistHash, err := fileDigest(sourceDefinition)
	if err != nil {
		return err
	}
	var release func()
	for attempt := 0; attempt < 100; attempt++ {
		release, err = d.lockHealthState()
		if !errors.Is(err, errHealthBusy) {
			break
		}
		if err := d.checkInterrupted(); err != nil {
			return err
		}
		d.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	defer func() {
		if release != nil {
			release()
		}
	}()
	legacy := filepath.Join(filepath.Dir(d.Tool), legacyHealthScript)
	backup, err := os.MkdirTemp("", "network-health-migration.")
	if err != nil {
		return err
	}
	fmt.Fprintln(d.Out, "Temporary health rollback staging:", backup)
	retain := false
	defer func() {
		if !retain {
			if err := os.RemoveAll(backup); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("health rollback staging retained at %s: %w", backup, err))
			} else if _, err := os.Lstat(backup); !os.IsNotExist(err) {
				resultErr = errors.Join(resultErr, fmt.Errorf("could not verify removal of health rollback staging %s", backup))
			} else {
				fmt.Fprintln(d.Out, "Temporary health rollback staging removed:", backup)
			}
		}
	}()
	records, err := d.snapshot(backup, []string{d.Tool, definition, legacy})
	if err != nil {
		return err
	}
	stopped, changed := false, false
	err = func() error {
		if err := d.checkInterrupted(); err != nil {
			return err
		}
		var err error
		stopped, err = d.stopHealthJob()
		if err != nil {
			return err
		}
		previousProbe := d.previousHealthProbe()
		changed = true
		if err := d.InstallFile(filepath.Join(d.Root, ToolName), d.Tool, 0o755); err != nil {
			return err
		}
		if err := d.InstallFile(sourceDefinition, definition, 0o644); err != nil {
			return err
		}
		release()
		release = nil
		if err := d.startHealthJob(); err != nil {
			return err
		}
		if err := d.waitNativeHealth(); err != nil {
			return err
		}
		fmt.Fprintln(d.Out, "Native job completed; waiting for its scheduled HTTP probe")
		if err := d.acceptHealthSample(previousProbe); err != nil {
			return err
		}
		if _, exists := before.Files[legacy]; exists {
			digest, err := fileDigest(legacy)
			if err != nil || digest != before.Files[legacy] {
				return errors.New("retired health script changed during migration")
			}
			if err := os.Remove(legacy); err != nil {
				return err
			}
		}
		before.Files[d.Tool], before.Files[definition] = toolHash, plistHash
		delete(before.Files, legacy)
		after, err := d.maintenanceState()
		if err != nil || !reflect.DeepEqual(before, after) {
			return errors.New("native health installed; unchanged core runtime could not be confirmed")
		}
		return d.checkInterrupted()
	}()
	if err == nil {
		fmt.Fprintln(d.Out, "Native Go health-check active; old health script removed; proxy, DNS and observer unchanged")
		return nil
	}
	if !stopped {
		return err
	}
	rollbackErr := func() error {
		if changed {
			if _, err := d.stopHealthJob(); err != nil {
				return err
			}
			if err := d.restore(backup, records); err != nil {
				return err
			}
		}
		if release != nil {
			release()
			release = nil
		}
		return d.startHealthJob()
	}()
	if rollbackErr != nil {
		retain = true
		fmt.Fprintln(d.Out, "Health rollback incomplete; recovery files retained:", backup)
		return fmt.Errorf("%w; rollback failed: %v", err, rollbackErr)
	}
	return err
}
