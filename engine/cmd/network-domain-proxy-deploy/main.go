// Command network-domain-proxy-deploy manages the independent proxy and its
// backups. Run the staged copy as administrator: install and
// upgrade read their inputs from the directory holding this program.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"

	"network-owned-engine/internal/deploy"
)

const usage = "usage: network-domain-proxy-deploy install|upgrade|enable|rollback|install-tool|install-health-maintenance|backups|inspect-backup <path>|remove-backup <path>|residues|cleanup-residues|cleanup-health-state"

func validArguments(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "install", "upgrade", "enable", "rollback", "install-tool", "install-health-maintenance", "backups", "residues", "cleanup-residues", "cleanup-health-state":
		return len(args) == 1
	case "inspect-backup", "remove-backup":
		return len(args) == 2
	}
	return false
}

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "--help" || os.Args[1] == "-h") {
		fmt.Println(usage)
		return
	}
	if !validArguments(os.Args[1:]) {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Administrator authorization required")
		os.Exit(1)
	}
	syscall.Umask(0o077)
	executable, err := os.Executable()
	if err == nil {
		executable, err = filepath.EvalSymlinks(executable)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	d := deploy.New(deploy.Production, filepath.Dir(executable), os.Stdout)
	// An interrupt takes effect at the next step boundary, where an upgrade
	// rolls back instead of leaving half-replaced files.
	var interrupted atomic.Bool
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for range signals {
			interrupted.Store(true)
		}
	}()
	d.Interrupted = interrupted.Load
	if err := run(d, os.Args[1:]...); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(d *deploy.Deployer, args ...string) error {
	if !validArguments(args) {
		return fmt.Errorf("%s", usage)
	}
	release, err := d.Lock()
	if err != nil {
		return err
	}
	defer release()
	switch args[0] {
	case "install", "upgrade":
		_, err = d.Upgrade(args[0] == "install")
	case "enable":
		err = d.Enable()
	case "rollback":
		err = d.Rollback()
	case "backups":
		var backups []deploy.Backup
		backups, err = d.Backups()
		if err == nil {
			err = json.NewEncoder(d.Out).Encode(backups)
		}
	case "inspect-backup":
		var backup deploy.Backup
		backup, err = d.InspectBackup(args[1])
		if err == nil {
			err = json.NewEncoder(d.Out).Encode(backup)
		}
	case "remove-backup":
		err = d.RemoveBackup(args[1])
	case "install-tool":
		err = d.InstallTool()
	case "install-health-maintenance":
		err = d.InstallHealthMaintenance()
	case "residues":
		var residues []deploy.Residue
		residues, err = d.Residues()
		if err == nil {
			err = json.NewEncoder(d.Out).Encode(residues)
		}
	case "cleanup-residues", "cleanup-health-state":
		err = d.CleanupResidues(args[0] == "cleanup-health-state")
	}
	return err
}
