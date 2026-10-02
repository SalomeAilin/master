// Command network-domain-proxy-deploy installs, upgrades, enables or rolls back
// the independent proxy. Run the staged copy as administrator: install and
// upgrade read their inputs from the directory holding this program.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sync/atomic"
	"syscall"

	"network-owned-engine/internal/deploy"
)

func main() {
	if len(os.Args) != 2 || !slices.Contains([]string{"install", "upgrade", "enable", "rollback"}, os.Args[1]) {
		fmt.Fprintln(os.Stderr, "usage: network-domain-proxy-deploy install|upgrade|enable|rollback")
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
	if err := run(d, os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(d *deploy.Deployer, action string) error {
	release, err := d.Lock()
	if err != nil {
		return err
	}
	defer release()
	switch action {
	case "install", "upgrade":
		_, err = d.Upgrade(action == "install")
	case "enable":
		err = d.Enable()
	default:
		err = d.Rollback()
	}
	return err
}
