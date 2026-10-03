package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"network-owned-engine/internal/statuspage"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	output := flag.String("output", "", "absolute existing status-page destination")
	state := flag.String("state", filepath.Join(home, "Library/Caches/network-split-log-guard.state"), "private status summary")
	log := flag.String("log", filepath.Join(home, "Library/Logs/network-split-log-guard.log"), "bounded private log")
	check := flag.Bool("check", false, "print read-only evidence without publishing")
	flag.Parse()
	if flag.NArg() != 0 || !*check && !filepath.IsAbs(*output) {
		fmt.Fprintln(os.Stderr, "specify -check or -output /absolute/path.html")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, deadline := context.WithTimeout(ctx, 90*time.Second)
	defer deadline()
	report := statuspage.New().Collect(ctx)
	if *check {
		err = json.NewEncoder(os.Stdout).Encode(report)
	} else {
		err = report.Publish(*output, *state, *log)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
