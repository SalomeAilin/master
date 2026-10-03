package healthcheck

import (
	"bytes"
	"context"
	"errors"
	"io"
	"network-owned-engine/internal/runtimecheck"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Job owns a single scheduled health run. Its dependency graph has no deploy package.
type Job struct {
	runtimecheck.Paths
	Context     context.Context
	Out         io.Writer
	Run         func(...string) (string, error)
	Now         func() time.Time
	Interrupted func() error
}

func ProductionJob(ctx context.Context) *Job {
	return &Job{Paths: runtimecheck.Production, Context: ctx, Out: os.Stdout, Run: runtimecheck.Run, Now: time.Now}
}
func (d *Job) healthRunner() *Runner {
	return &Runner{StatePath: filepath.Join(d.BackupParent, healthState), LogPath: d.HealthLog, ConfigPath: d.Config, Now: d.Now, Run: d.Run}
}
func (d *Job) checkInterrupted() error {
	if d.Interrupted != nil {
		return d.Interrupted()
	}
	return d.Context.Err()
}
func (d *Job) maintenanceState() (runtimecheck.State, error) {
	return runtimecheck.Inspect(d.Paths, d.Run)
}
func (d *Job) backupParent() (*os.Root, error) { return runtimecheck.OpenRoot(d.BackupParent) }

// HealthCheck owns the existing state lock for cleanup, probing and publication.
// It does not acquire the proxy deployment lock or start another process of itself.
func (d *Job) HealthCheck() error {
	release, err := d.lockHealthState()
	if errors.Is(err, ErrBusy) {
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
