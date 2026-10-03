package deploy

import (
	"errors"
	"fmt"
	"network-owned-engine/internal/healthcheck"
	"os"
	"path/filepath"
	"time"
)

const healthLabel = "system/com.local.network-split-domestic-health"
const healthPlistName = "com.local.network-split-domestic-health.plist"

func (d *Deployer) healthJob() *healthcheck.Job {
	return &healthcheck.Job{Paths: d.Paths, Context: d.Context, Out: d.Out, Run: d.Run, Now: d.Now, Interrupted: d.checkInterrupted}
}

func (d *Deployer) previousHealthProbe() int64 {
	state, err := healthcheck.Read(filepath.Join(d.BackupParent, healthState), d.Now().Unix())
	if err != nil {
		return 0
	}
	return state.LastProbe
}

func (d *Deployer) acceptHealthSample(previous int64) error {
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
