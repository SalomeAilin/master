package deploy

import (
	"fmt"
	"network-owned-engine/internal/healthcheck"
	"path/filepath"
	"testing"
	"time"
)

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
