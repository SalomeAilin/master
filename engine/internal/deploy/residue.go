package deploy

import (
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
)

var errHealthBusy = healthcheck.ErrBusy

type Residue = healthcheck.Residue

func lockState(path string) (func(), error)          { return healthcheck.LockState(path) }
func (d *Deployer) lockHealthState() (func(), error) { return lockState(d.HealthLock) }
func (d *Deployer) Residues() ([]Residue, error)     { return d.healthJob().Residues() }
func (d *Deployer) CleanupResidues(healthOnly bool) error {
	return d.healthJob().CleanupResidues(healthOnly)
}
