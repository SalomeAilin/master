package deploy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"time"

	"network-owned-engine/internal/runtimecheck"
	"network-owned-engine/internal/service"
	"network-owned-engine/internal/statuspage"
)

type retryableAcceptance struct{ error }

func (e *retryableAcceptance) Unwrap() error { return e.error }

var errStatusNotFresh = errors.New("status receipt is not fresh")

func retryableProbe(err error) error {
	var network net.Error
	if err != nil && (errors.As(err, &network) && network.Timeout() || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED)) {
		return &retryableAcceptance{err}
	}
	return err
}

func retryableHTTP(err error) error {
	// Certificate errors, invocation failures and local permission errors are
	// not transport retries. Every successful attempt still uses curl -f and TLS.
	if code, ok := exitCode(err); ok && slices.Contains([]int{5, 6, 7, 18, 22, 28, 35, 52, 55, 56}, code) {
		return &retryableAcceptance{err}
	}
	return err
}

func statusAcceptance(s statuspage.Snapshot) error {
	if len(s.Checks) == 0 || len(s.Domains) == 0 {
		return errors.New("status receipt is incomplete")
	}
	failed, networkOnly := false, true
	var details []string
	for _, row := range s.Checks {
		if row.State == "ok" {
			continue
		}
		failed = true
		details = append(details, row.Name+" ("+row.State+")")
		if row.State != "bad" || !slices.Contains([]string{"https://www.google.com/generate_204", "https://claude.ai/", "https://api.anthropic.com/"}, row.Name) {
			networkOnly = false
		}
	}
	for _, row := range s.Domains {
		if row.State == "wired" || row.State == "policy-excluded" {
			continue
		}
		failed = true
		details = append(details, row.Name+" ("+row.State+")")
		if row.State != "unknown" || row.Detail != "DNS lookup failed" {
			networkOnly = false
		}
	}
	if s.State == "OK" && !failed {
		return nil
	}
	if len(details) > 8 {
		details = details[:8]
	}
	err := fmt.Errorf("status receipt did not contain healthy checks and domains: %s", strings.Join(details, ", "))
	if s.State == "BAD" && failed && networkOnly {
		return &retryableAcceptance{err}
	}
	return err
}

func (d *Deployer) acceptanceRounds(round func(int) error) error {
	previousContext := d.Context
	ctx, cancel := context.WithTimeout(previousContext, 10*time.Minute)
	d.Context = ctx
	defer func() { cancel(); d.Context = previousContext }()
	for attempt := 0; attempt < 3; attempt++ {
		if err := d.checkInterrupted(); err != nil {
			return err
		}
		err := round(attempt)
		if interrupted := d.checkInterrupted(); interrupted != nil {
			return interrupted
		}
		if err == nil {
			fmt.Fprintf(d.Out, "Complete acceptance round %d/3 passed\n", attempt+1)
			return nil
		}
		var transient *retryableAcceptance
		if !errors.As(err, &transient) {
			return err
		}
		fmt.Fprintf(d.Out, "Acceptance round %d/3 failed a network check: %v\n", attempt+1, err)
		if attempt == 2 {
			return fmt.Errorf("complete acceptance failed after three rounds: %w", err)
		}
		d.Sleep(5 * time.Second)
	}
	return errors.New("acceptance retry limit reached")
}

func (d *Deployer) acceptanceState(c service.Config) (runtimecheck.State, error) {
	if d.unifiedLayout == nil {
		if err := service.CheckInstallation(c); err != nil {
			return runtimecheck.State{}, err
		}
	}
	layout := d.layout(c)
	p := d.Paths
	p.Tool, p.ServiceConfig, p.SupervisorPlist = d.Binary, layout.Config, layout.MainPlist
	p.Plist, p.NativeDNS = filepath.Join(layout.Jobs, PlistName), c.Version == 2
	state, err := runtimecheck.Inspect(p, d.Run)
	if err != nil {
		return state, err
	}
	if d.unifiedLayout == nil {
		for path := range state.Files {
			mode := os.FileMode(0o644)
			if path == d.Binary {
				mode = 0o755
			}
			if c.Version == 1 && path == c.Routes.DNSBinary {
				mode = 0o555
			}
			if path == layout.Config {
				mode = 0o600
			}
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
				return state, fmt.Errorf("installed file type or permissions changed: %s", path)
			}
			stat := info.Sys().(*syscall.Stat_t)
			if stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
				return state, fmt.Errorf("installed file ownership changed: %s", path)
			}
		}
		installed, err := service.Load(layout.Config, true)
		if err != nil || installed != c {
			return state, errors.New("installed service configuration changed")
		}
		for _, path := range []string{c.Routes.ChinaList, c.Routes.ExtraList, c.Routes.DomainList} {
			digest, err := fileDigest(path)
			if err != nil {
				return state, err
			}
			state.Files[path] = digest
		}
	}
	candidate, err := fileDigest(filepath.Join(d.Root, EngineName))
	if err != nil || state.Files[d.Binary] != candidate {
		return state, errors.New("installed program differs from the tested candidate")
	}
	for _, job := range d.managedJobs(c) {
		want, err := service.Plist(job.Definition)
		if err != nil {
			return state, err
		}
		got, err := os.ReadFile(job.Path())
		if err != nil || string(want) != string(got) {
			return state, fmt.Errorf("worker definition changed: %s", job.Label)
		}
	}
	return state, nil
}

func sameAcceptanceState(before, after runtimecheck.State) error {
	if !reflect.DeepEqual(before, after) {
		return errors.New("service PIDs or installed files changed during acceptance")
	}
	return nil
}

func (d *Deployer) refreshStatus(c service.Config) error {
	for _, job := range d.managedJobs(c) {
		if job.Label != "com.local.network-split-log-guard" {
			continue
		}
		for attempt := 0; attempt < 46; attempt++ {
			if err := d.checkInterrupted(); err != nil {
				return err
			}
			out, err := d.Run("/bin/launchctl", "print", "system/"+job.Label)
			if err != nil {
				return err
			}
			info := service.ParseLaunch(out)
			if !job.Matches(info) {
				return errors.New("status task identity changed before refresh")
			}
			if info.Exit != "0" {
				return errors.New("status task did not exit successfully before refresh")
			}
			if info.State == "not running" {
				_, err = d.Run("/bin/launchctl", "kickstart", "system/"+job.Label)
				return err
			}
			if attempt < 45 {
				d.Sleep(2 * time.Second)
			}
		}
		return errors.New("status task did not finish before refresh")
	}
	return errors.New("status task is missing")
}

func (d *Deployer) waitStatusReport(c service.Config, since time.Time) error {
	for attempt := 0; attempt < 46; attempt++ {
		if err := d.checkInterrupted(); err != nil {
			return err
		}
		err := acceptStatusReport(c, since)
		if !errors.Is(err, errStatusNotFresh) {
			return err
		}
		if attempt == 45 {
			return errors.New("status task did not publish a fresh receipt within 90 seconds")
		}
		d.Sleep(2 * time.Second)
	}
	return errStatusNotFresh
}
