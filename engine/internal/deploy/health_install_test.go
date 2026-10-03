package deploy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"network-owned-engine/internal/healthcheck"
)

type healthMigration struct {
	loaded     bool
	fault      string
	failed     bool
	sawRunning bool
}

func healthMigrationFixture(t *testing.T) (*Deployer, *healthMigration) {
	t.Helper()
	d := maintenanceFixture(t)
	f := &healthMigration{loaded: true}
	d.PreflightHealth = func() error {
		if f.fault == "preflight" {
			return errors.New("probe failed")
		}
		return nil
	}
	d.Sleep = func(time.Duration) {}
	d.AcceptHealth = func(int64) error {
		if f.fault == "sample" {
			return errors.New("scheduled probe failed")
		}
		return nil
	}
	writeTestFile(t, filepath.Join(d.Root, ToolName), "native maintenance tool")
	writeTestFile(t, filepath.Join(d.Root, filepath.Base(d.healthBinary())), "independent native health runtime")
	for _, item := range []struct {
		path string
		args []any
	}{
		{d.healthDefinition(), []any{filepath.Join(filepath.Dir(d.Tool), legacyHealthScript)}},
		{filepath.Join(d.Root, healthPlistName), []any{d.healthBinary()}},
	} {
		data, _ := json.Marshal(map[string]any{"Label": strings.TrimPrefix(healthLabel, "system/"), "ProgramArguments": item.args, "RunAtLoad": true, "StartInterval": 30})
		writeTestFile(t, item.path, string(data))
	}
	original := d.Run
	d.Run = func(args ...string) (string, error) {
		if args[0] == "/usr/bin/plutil" {
			data, err := os.ReadFile(args[len(args)-1])
			return string(data), err
		}
		if args[0] == "/bin/launchctl" && (len(args) > 2 && args[2] == healthLabel || len(args) > 3 && args[3] == d.healthDefinition()) {
			var config struct {
				Arguments []string `json:"ProgramArguments"`
			}
			data, err := os.ReadFile(d.healthDefinition())
			if err != nil {
				return "", err
			}
			if err := json.Unmarshal(data, &config); err != nil {
				return "", err
			}
			native := config.Arguments[0] == d.healthBinary()
			switch args[1] {
			case "print":
				if !f.loaded {
					return "", &CommandError{Args: args, Code: 113}
				}
				if native && f.fault == "running-first" && !f.sawRunning {
					f.sawRunning = true
					return fmt.Sprintf("program = %s\nstate = running\nruns = 1\nlast exit code = (never exited)\n", d.healthBinary()), nil
				}
				code := "0"
				if native && f.fault == "activation" {
					code = "1"
				}
				return fmt.Sprintf("program = %s\nstate = not running\nruns = 1\nlast exit code = %s\n", config.Arguments[0], code), nil
			case "bootout":
				if f.fault == "bootout" && !f.failed {
					f.failed = true
					return "", &CommandError{Args: args, Code: 1}
				}
				f.loaded = false
				return "", nil
			case "bootstrap":
				if f.fault == "rollback" || native && f.fault == "bootstrap" {
					return "", &CommandError{Args: args, Code: 1}
				}
				f.loaded = true
				return "", nil
			}
			t.Fatal("unexpected health service mutation", args)
		}
		return original(args...)
	}
	return d, f
}

func rollbackPath(d *Deployer) string {
	for _, line := range strings.Split(fmt.Sprint(d.Out), "\n") {
		if path, ok := strings.CutPrefix(line, "Temporary health rollback staging: "); ok {
			return path
		}
	}
	return ""
}

func TestNativeHealthMigrationPreservesCoreAndRetiresShell(t *testing.T) {
	d, f := healthMigrationFixture(t)
	f.fault = "running-first"
	active := makeResidue(t, d, healthState, "active state", true)
	before, err := d.maintenanceState()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.InstallHealthMaintenance(); err != nil {
		t.Fatal(err)
	}
	after, err := d.maintenanceState()
	if err != nil {
		t.Fatal(err)
	}
	before.Files[d.Tool] = after.Files[d.Tool]
	before.Files[d.healthDefinition()] = after.Files[d.healthDefinition()]
	before.Files[d.healthBinary()] = after.Files[d.healthBinary()]
	delete(before.Files, filepath.Join(filepath.Dir(d.Tool), legacyHealthScript))
	if !reflect.DeepEqual(before, after) || !f.loaded || !f.sawRunning {
		t.Fatal("runtime or activation mismatch")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(d.Tool), legacyHealthScript)); !os.IsNotExist(err) {
		t.Fatal("shell entry retained", err)
	}
	if data, _ := os.ReadFile(active); string(data) != "active state" {
		t.Fatal("active state changed")
	}
	if path := rollbackPath(d); path == "" {
		t.Fatal("missing staging record")
	} else if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("rollback staging retained", path, err)
	}
}

func TestNativeHealthMigrationRollsBackFailures(t *testing.T) {
	for _, fault := range []string{"preflight", "bootout", "publication", "bootstrap", "activation", "sample"} {
		t.Run(fault, func(t *testing.T) {
			d, f := healthMigrationFixture(t)
			f.fault = fault
			if fault == "publication" {
				d.Rename = func(source, target string) error {
					if target == d.healthDefinition() && !f.failed {
						f.failed = true
						return errors.New("publication failed")
					}
					return os.Rename(source, target)
				}
			}
			before, err := d.maintenanceState()
			if err != nil {
				t.Fatal(err)
			}
			if err := d.InstallHealthMaintenance(); err == nil {
				t.Fatal("failure ignored")
			}
			after, err := d.maintenanceState()
			if err != nil || !reflect.DeepEqual(before, after) || !f.loaded {
				t.Fatal("rollback incomplete", err)
			}
			if path := rollbackPath(d); path != "" {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("rollback staging retained", path, err)
				}
			}
		})
	}
}

func TestFailedNativeHealthRollbackRetainsRecoveryFiles(t *testing.T) {
	d, f := healthMigrationFixture(t)
	f.fault = "rollback"
	if err := d.InstallHealthMaintenance(); err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatal(err)
	}
	path := rollbackPath(d)
	if path == "" {
		t.Fatal("recovery path not reported")
	}
	t.Cleanup(func() { os.RemoveAll(path) })
	if _, err := os.Stat(filepath.Join(path, "manifest.json")); err != nil {
		t.Fatal(err)
	}
}

func TestHealthDefinitionCannotChangeOtherServiceSettings(t *testing.T) {
	d, _ := healthMigrationFixture(t)
	path := filepath.Join(d.Root, healthPlistName)
	data, _ := os.ReadFile(path)
	writeTestFile(t, path, strings.Replace(string(data), `"StartInterval":30`, `"StartInterval":1`, 1))
	if err := d.InstallHealthMaintenance(); err == nil {
		t.Fatal("changed schedule accepted")
	}
}

func TestScheduledHealthAcceptanceRequiresNewHealthySample(t *testing.T) {
	for _, healthy := range []bool{true, false} {
		t.Run(fmt.Sprint(healthy), func(t *testing.T) {
			d := maintenanceFixture(t)
			d.Now = func() time.Time { return time.Unix(1000, 0) }
			state := healthcheck.State{Interval: 30, LastProbe: 990}
			writeTestFile(t, filepath.Join(d.BackupParent, healthState), string(state.Encode()))
			waits := 0
			d.Sleep = func(time.Duration) {
				waits++
				state.LastProbe = 1000
				if !healthy {
					state.Failures = 1
				}
				writeTestFile(t, filepath.Join(d.BackupParent, healthState), string(state.Encode()))
			}
			err := d.acceptHealthSample(990)
			if (err == nil) != healthy || waits == 0 || waits > 30 {
				t.Fatal(healthy, waits, err)
			}
		})
	}
}

func TestMigrationCapturesProbeAfterOldWriterStops(t *testing.T) {
	d, _ := healthMigrationFixture(t)
	d.Now = func() time.Time { return time.Unix(1000, 0) }
	original := d.Run
	written := false
	d.Run = func(args ...string) (string, error) {
		if len(args) == 3 && args[0] == "/bin/launchctl" && args[1] == "bootout" && args[2] == healthLabel && !written {
			written = true
			state := healthcheck.State{Interval: 120, LastProbe: 999}
			writeTestFile(t, filepath.Join(d.BackupParent, healthState), string(state.Encode()))
		}
		return original(args...)
	}
	d.AcceptHealth = func(previous int64) error {
		if previous != 999 {
			return fmt.Errorf("old writer sample was not captured: %d", previous)
		}
		return nil
	}
	if err := d.InstallHealthMaintenance(); err != nil {
		t.Fatal(err)
	}
}
