package deploy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

const routeGuardName = "network-split-guard.sh"

// InstallRouteGuard publishes only the existing guard, while holding the same
// POSIX lock as its scheduled instances. No service is restarted.
func (d *Deployer) InstallRouteGuard() (resultErr error) {
	source := filepath.Join(d.Root, routeGuardName)
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 128<<10 {
		return errors.New("invalid staged route guard")
	}
	if _, err := d.Run("/bin/zsh", "-n", source); err != nil {
		return err
	}
	digest, err := fileDigest(source)
	if err != nil {
		return err
	}
	var release func()
	for attempt := 0; attempt < 60; attempt++ {
		release, err = lockState(filepath.Join(d.BackupParent, "network-split-guard.flock"))
		if !errors.Is(err, errHealthBusy) {
			break
		}
		if err := d.checkInterrupted(); err != nil {
			return err
		}
		d.Sleep(time.Second)
	}
	if err != nil {
		return fmt.Errorf("route guard is busy or its lock is unsafe: %w", err)
	}
	defer release()
	before, err := d.maintenanceState()
	if err != nil {
		return err
	}
	target := filepath.Join(filepath.Dir(d.Tool), routeGuardName)
	backup, err := os.MkdirTemp("", "network-guard-upgrade.")
	if err != nil {
		return err
	}
	fmt.Fprintln(d.Out, "Temporary guard rollback staging:", backup)
	retain := false
	defer func() {
		if retain {
			fmt.Fprintln(d.Out, "Guard recovery files retained:", backup)
			return
		}
		if err := os.RemoveAll(backup); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("could not remove guard staging %s: %w", backup, err))
		} else if _, err := os.Lstat(backup); !os.IsNotExist(err) {
			resultErr = errors.Join(resultErr, fmt.Errorf("could not verify removal of guard staging %s", backup))
		} else {
			fmt.Fprintln(d.Out, "Temporary guard rollback staging removed:", backup)
		}
	}()
	records, err := d.snapshot(backup, []string{target})
	if err != nil {
		return err
	}
	err = func() error {
		if err := d.checkInterrupted(); err != nil {
			return err
		}
		if err := d.InstallFile(source, target, 0o755); err != nil {
			return err
		}
		before.Files[target] = digest
		after, err := d.maintenanceState()
		if err != nil || !reflect.DeepEqual(before, after) {
			return errors.New("route guard installed; its digest and unchanged runtime could not be confirmed")
		}
		return d.checkInterrupted()
	}()
	if err != nil {
		if rollbackErr := d.restore(backup, records); rollbackErr != nil {
			retain = true
			return fmt.Errorf("%w; guard rollback failed: %v", err, rollbackErr)
		}
		return err
	}
	fmt.Fprintln(d.Out, "Route guard installed; proxy, DNS and observer PIDs and other installed hashes unchanged")
	return nil
}
