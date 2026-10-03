package deploy

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"network-owned-engine/internal/healthcheck"
)

const healthLabel = "system/com.local.network-split-domestic-health"
const healthPlistName = "com.local.network-split-domestic-health.plist"

func (d *Deployer) healthRunner() *healthcheck.Runner {
	return &healthcheck.Runner{StatePath: filepath.Join(d.BackupParent, healthState),
		LogPath: d.HealthLog, ConfigPath: d.Config, Now: d.Now, Run: d.Run}
}

// HealthCheck owns the existing state lock for cleanup, probing and publication.
// It does not acquire the proxy deployment lock or start another process of itself.
func (d *Deployer) HealthCheck() error {
	release, err := d.lockHealthState()
	if errors.Is(err, errHealthBusy) {
		return nil
	}
	if err != nil {
		return err
	}
	defer release()
	runner := d.healthRunner()
	var output bytes.Buffer
	previous := d.Out
	d.Out = &output
	err = d.cleanupResiduesLocked(true)
	d.Out = previous
	if err != nil {
		if err := runner.Logf("state cleanup deferred: %v", err); err != nil {
			return err
		}
	} else if message := strings.TrimSpace(output.String()); message != "" {
		if err := runner.Logf("%s", message); err != nil {
			return err
		}
	}
	return runner.RunOnce(d.Context)
}

func (d *Deployer) preflightHealth() error {
	if d.PreflightHealth != nil {
		return d.PreflightHealth()
	}
	outcome := d.healthRunner().Check(d.Context)
	if !outcome.Healthy {
		if outcome.Err != nil {
			return fmt.Errorf("native health preflight failed: %s (HTTP %d): %w", outcome.Reason, outcome.Status, outcome.Err)
		}
		return fmt.Errorf("native health preflight failed: %s (HTTP %d)", outcome.Reason, outcome.Status)
	}
	fmt.Fprintf(d.Out, "Native Go health probe accepted: HTTP %d, %d ms, wired route verified\n", outcome.Status, outcome.ElapsedMS)
	return nil
}
