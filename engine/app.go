package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"syscall"
	"time"

	"network-owned-engine/internal/deploy"
	"network-owned-engine/internal/dnsobserver"
	"network-owned-engine/internal/evidence"
	"network-owned-engine/internal/healthcheck"
	"network-owned-engine/internal/policy"
	"network-owned-engine/internal/proxyconfig"
	"network-owned-engine/internal/routing"
	"network-owned-engine/internal/runtimecheck"
	"network-owned-engine/internal/service"
	"network-owned-engine/internal/statuspage"
)

func applicationCommand(args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "service", "worker", "prepare-service", "check-service", "config", "status", "evidence", "upgrade", "maintenance":
	default:
		return false, nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var err error
	switch args[0] {
	case "evidence":
		err = evidence.Run(args[1:])
	case "upgrade":
		if len(args) > 2 {
			return true, errors.New("usage: network-domain-engine upgrade [service.json]")
		}
		config := service.ConfigPath
		if len(args) == 2 {
			config = args[1]
		}
		executable, e := os.Executable()
		if e != nil {
			return true, e
		}
		executable, e = filepath.EvalSymlinks(executable)
		if e != nil {
			return true, e
		}
		_, err = deploy.Consolidate(ctx, filepath.Dir(executable), config, os.Stdout, false)
	case "maintenance":
		err = maintenanceCommand(ctx, args[1:])
	case "service", "check-service":
		flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		path := flags.String("c", service.ConfigPath, "unified service configuration")
		live := flags.Bool("live", false, "run the isolated proxy preflight without installing")
		if err = flags.Parse(args[1:]); err == nil {
			if flags.NArg() != 0 {
				return true, errors.New("positional service arguments rejected")
			}
			if args[0] == "service" {
				if *live {
					return true, errors.New("live preflight is only available with check-service")
				}
				err = service.Run(ctx, *path)
			} else if *live {
				executable, e := os.Executable()
				if e != nil {
					return true, e
				}
				_, err = deploy.Consolidate(ctx, filepath.Dir(executable), *path, os.Stdout, true)
			} else {
				_, err = service.Load(*path, false)
			}
		}
	case "worker":
		err = worker(ctx, args[1:])
	case "prepare-service":
		if len(args) != 2 {
			return true, errors.New("usage: network-domain-engine prepare-service output.json")
		}
		var account *user.User
		account, err = user.Current()
		if err != nil {
			break
		}
		var c service.Config
		c, err = service.Prepare(account, runtimecheck.Run)
		if err != nil {
			break
		}
		var data []byte
		data, err = json.MarshalIndent(c, "", "  ")
		if err == nil {
			err = service.WriteNew(args[1], append(data, '\n'))
		}
	case "config":
		err = configCommand(args[1:])
	case "status":
		if len(args) != 1 {
			return true, errors.New("usage: network-domain-engine status")
		}
		err = statusCommand(ctx, []string{"-check"}, false)
	}
	if err == context.Canceled || errors.Is(err, flag.ErrHelp) {
		err = nil
	}
	return true, err
}

func maintenanceCommand(ctx context.Context, args []string) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Println("maintenance: backups | inspect-backup <exact-path> | remove-backup <exact-path> | residues | cleanup-residues | enable | rollback")
		return nil
	}
	if !validMaintenanceArguments(args) {
		return errors.New("invalid maintenance arguments")
	}
	if os.Geteuid() != 0 {
		return errors.New("administrator authorization required")
	}
	paths := runtimecheck.Unified()
	if _, err := os.Stat(service.PlistPath); os.IsNotExist(err) {
		paths = runtimecheck.Production
	} else if err != nil {
		return err
	}
	d := deploy.New(paths, "", os.Stdout)
	d.Context = ctx
	d.Interrupted = func() bool { return ctx.Err() != nil }
	return runMaintenance(d, args)
}

func validMaintenanceArguments(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "backups", "residues", "cleanup-residues", "enable", "rollback":
		return len(args) == 1
	case "inspect-backup", "remove-backup":
		return len(args) == 2
	default:
		return false
	}
}

func runMaintenance(d *deploy.Deployer, args []string) error {
	if !validMaintenanceArguments(args) {
		return errors.New("invalid maintenance arguments")
	}
	release, err := d.Lock()
	if err != nil {
		return err
	}
	defer release()
	var result any
	switch args[0] {
	case "backups":
		result, err = d.Backups()
	case "inspect-backup":
		result, err = d.InspectBackup(args[1])
	case "remove-backup":
		err = d.RemoveBackup(args[1])
	case "residues":
		result, err = d.Residues()
	case "cleanup-residues":
		err = d.CleanupResidues(false)
	case "enable":
		err = d.Enable()
	case "rollback":
		err = d.Rollback()
	}
	if err == nil && result != nil {
		err = json.NewEncoder(d.Out).Encode(result)
	}
	return err
}

func configCommand(args []string) error {
	flags := flag.NewFlagSet("config", flag.ContinueOnError)
	dir := flags.String("policy-dir", "", "repository policy directory")
	rules := flags.String("rules-directory", "", "installed seed directory")
	cache := flags.String("cache-path", "", "private rule cache")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: network-domain-engine config [flags] output.json")
	}
	if *dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		*dir, err = proxyconfig.FindPolicyDir(wd)
		if err != nil {
			return err
		}
	}
	c, err := proxyconfig.Build(*dir, *rules, *cache)
	if err != nil {
		return err
	}
	data, err := proxyconfig.Encode(c)
	if err != nil {
		return err
	}
	return service.WriteNew(flags.Arg(0), data)
}

func worker(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("missing worker role")
	}
	if args[0] == "status" {
		if os.Geteuid() == 0 {
			return errors.New("status publishing requires its unprivileged account")
		}
		return statusCommand(ctx, args[1:], true)
	}
	if os.Geteuid() != 0 {
		return errors.New("routing workers require administrator privileges")
	}
	syscall.Umask(0o077)
	flags := flag.NewFlagSet("worker", flag.ContinueOnError)
	path := flags.String("service-config", service.ConfigPath, "installed service configuration")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *path != service.ConfigPath {
		return errors.New("unexpected worker configuration")
	}
	c, err := service.Load(*path, true)
	if err != nil {
		return err
	}
	switch args[0] {
	case "guard", "routes":
		routes := c.Routes
		if args[0] == "routes" {
			routes.GuardLog = routes.ChinaLog
		}
		g := routing.New(routes)
		g.Run = func(args ...string) (string, error) { return runtimecheck.RunContext(ctx, 8*time.Second, args...) }
		if args[0] == "guard" {
			return g.RunOnce(ctx)
		}
		return g.Rebuild(ctx)
	case "health":
		job := healthcheck.ProductionJob(ctx)
		job.Paths = runtimecheck.Unified()
		return job.HealthCheck()
	case "observe":
		log := dnsobserver.NewLogger("/var/log/network-split-dns-event-route-agent.log")
		defer log.Close()
		router := &dnsobserver.Router{Policy: policy.New(c.Routes.ChinaList, c.Routes.ExtraList), Command: dnsobserver.RunCommand, Log: log, Gateway: c.Routes.WiredGateway, Interface: c.Routes.WiredInterface}
		follower := &dnsobserver.Follower{LogPath: "/var/log/dnsmasq-network-split-query.log", ConfigPath: c.Routes.DNSConfig, MaxBytes: dnsobserver.MaxQueryLogBytes,
			Correlator: dnsobserver.NewCorrelator(nil, router.Bind), Log: log, Sleep: time.Sleep}
		return follower.Run(ctx)
	default:
		return errors.New("unknown worker role")
	}
}

func statusCommand(ctx context.Context, args []string, unified bool) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	output := flags.String("output", "", "existing status HTML destination")
	state := flags.String("state", filepath.Join(home, "Library/Caches/network-split-log-guard.state"), "status state")
	log := flags.String("log", filepath.Join(home, "Library/Logs/network-split-log-guard.log"), "status log")
	check := flags.Bool("check", false, "collect without publishing")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !*check && !filepath.IsAbs(*output) {
		return errors.New("invalid status arguments")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	collector := statuspage.New()
	if !unified {
		out, e := runtimecheck.RunContext(ctx, 4*time.Second, "/bin/launchctl", "print", "system/"+service.Label)
		unified = e == nil && service.ParseLaunch(out).Program == service.Binary
	}
	if unified {
		collector.Launchd = service.JobsDirectory
		collector.ObserverProgram = service.Binary
	}
	report := collector.Collect(ctx)
	if ctx.Err() == context.Canceled {
		return ctx.Err()
	}
	if *check {
		fmt.Printf("state=%s checked=%s checks=%d domain_routes=%d\n", report.State, report.Updated.Format(time.RFC3339), len(report.Checks), len(report.Domains))
		for _, row := range append(report.Checks, report.Domains...) {
			if row.State == "bad" || row.State == "drift" || row.State == "unknown" {
				fmt.Printf("%s: %s %s\n", row.Name, row.State, row.Detail)
			}
		}
		return nil
	}
	if err := report.Publish(*output, *state, *log); err != nil {
		return errors.Join(err, statuspage.RecordFailure(*state, *log, err))
	}
	return nil
}
