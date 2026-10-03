package deploy

import (
	"fmt"
	"path/filepath"

	"network-owned-engine/internal/healthcheck"
)

const healthLabel = "system/com.local.network-split-domestic-health"
const healthPlistName = "com.local.network-split-domestic-health.plist"

func (d *Deployer) healthRunner() *healthcheck.Runner {
	return &healthcheck.Runner{StatePath: filepath.Join(d.BackupParent, healthState),
		LogPath: d.HealthLog, ConfigPath: d.Config, Now: d.Now, Run: d.Run}
}

func (d *Deployer) healthJob() *healthcheck.Job {
	return &healthcheck.Job{Paths: d.Paths, Context: d.Context, Out: d.Out, Run: d.Run, Now: d.Now, Interrupted: d.checkInterrupted}
}

func (d *Deployer) HealthCheck() error { return d.healthJob().HealthCheck() }

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
