// Command network-split-health runs one scheduled health cycle. It exposes no
// installation, backup removal or proxy upgrade command.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"network-owned-engine/internal/healthcheck"
)

func run(job *healthcheck.Job, args []string) error {
	if len(args) != 0 {
		return errors.New("usage: network-split-health (no arguments)")
	}
	return job.HealthCheck()
}

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "--help" || os.Args[1] == "-h") {
		fmt.Println("usage: network-split-health (one scheduled health cycle)")
		return
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Administrator authorization required")
		os.Exit(1)
	}
	syscall.Umask(0o077)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(healthcheck.ProductionJob(ctx), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
