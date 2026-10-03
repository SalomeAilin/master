package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"network-owned-engine/internal/runtimecheck"
	"network-owned-engine/internal/service"
)

type unifiedLayout struct {
	MainPlist, Config, Jobs, LegacyJobs, UserPlist, Newsyslog, Sbin, OldStatus, UserHome string
}

func (d *Deployer) layout(c service.Config) unifiedLayout {
	if d.unifiedLayout != nil {
		return *d.unifiedLayout
	}
	return unifiedLayout{MainPlist: service.PlistPath, Config: service.ConfigPath, Jobs: service.JobsDirectory, LegacyJobs: "/Library/LaunchDaemons",
		UserPlist: filepath.Join(c.Status.Home, "Library/LaunchAgents/com.local.network-split-log-guard.plist"), Newsyslog: "/etc/newsyslog.d/network-split.conf", Sbin: "/usr/local/sbin",
		OldStatus: filepath.Join(c.Status.Home, ".local/share/network-split-log-guard/network-split-status"), UserHome: c.Status.Home}
}

func (d *Deployer) managedJobs(c service.Config) []service.Job {
	layout := d.layout(c)
	jobs := service.Jobs(c)
	for i := range jobs {
		jobs[i].Directory = layout.Jobs
		args := append([]string(nil), jobs[i].Arguments()...)
		if args[0] == service.Binary {
			args[0] = d.Binary
		}
		for j := range args {
			if j > 0 && args[j-1] == "-service-config" {
				args[j] = layout.Config
			}
		}
		jobs[i].Definition["ProgramArguments"] = args
	}
	return jobs
}

type installedJob struct {
	Domain, Label, Path, Program string
	PID                          int
	Loaded                       bool
}

func (d *Deployer) inspectInstalledJob(job installedJob) (installedJob, error) {
	job.Loaded, job.PID = false, 0
	out, err := d.Run("/bin/launchctl", "print", job.Domain+"/"+job.Label)
	if code, known := exitCode(err); known && code == 113 {
		return job, nil
	}
	if err != nil {
		return job, err
	}
	info := service.ParseLaunch(out)
	if info.Path != job.Path || info.Program != job.Program {
		return job, fmt.Errorf("refusing unexpected job %s", job.Label)
	}
	job.Loaded, job.PID = true, info.PID
	return job, nil
}

func (d *Deployer) stopInstalledJob(job installedJob) error {
	current, err := d.inspectInstalledJob(job)
	if err != nil {
		return err
	}
	if !current.Loaded {
		return nil
	}
	if _, err := d.Run("/bin/launchctl", "bootout", job.Domain+"/"+job.Label); err != nil {
		return err
	}
	limit := 150
	if job.Label == service.Label {
		limit = (service.ParentExitTimeout + 5) * 10
	}
	for attempt := 0; current.PID > 0 && attempt < limit; attempt++ {
		alive, err := d.ProcessAlive(current.PID)
		if err != nil {
			return err
		}
		if !alive {
			return nil
		}
		d.Sleep(100 * time.Millisecond)
	}
	if current.PID > 0 {
		return fmt.Errorf("worker did not exit: %s", job.Label)
	}
	return nil
}

func (d *Deployer) bootstrapJob(job installedJob) error {
	for attempt := 0; attempt < 10; attempt++ {
		_, err := d.Run("/bin/launchctl", "bootstrap", job.Domain, job.Path)
		if code, known := exitCode(err); err == nil || !known || code != 5 || attempt == 9 {
			return err
		}
		d.Sleep(500 * time.Millisecond)
	}
	return errors.New("bootstrap retry exhausted")
}

func (d *Deployer) legacyJobs(c service.Config, uid string) []installedJob {
	layout := d.layout(c)
	var jobs []installedJob
	for _, pair := range [][2]string{{"homebrew.mxcl.dnsmasq", c.Routes.DNSBinary}, {"com.local.network-domain-proxy", d.Binary},
		{"com.local.network-split-dns-event-route-agent", filepath.Join(layout.Sbin, "network-split-dns-event-route-agent")}, {"com.local.china-route", filepath.Join(layout.Sbin, "china-route.sh")},
		{"com.local.network-split-guard", filepath.Join(layout.Sbin, "network-split-guard.sh")}, {"com.local.network-split-domestic-health", filepath.Join(layout.Sbin, "network-split-health")}} {
		jobs = append(jobs, installedJob{Domain: "system", Label: pair[0], Path: filepath.Join(layout.LegacyJobs, pair[0]+".plist"), Program: pair[1]})
	}
	return append(jobs, installedJob{Domain: "gui/" + uid, Label: "com.local.network-split-log-guard", Path: layout.UserPlist, Program: layout.OldStatus})
}

func (d *Deployer) unifiedJobs(c service.Config) []installedJob {
	var jobs []installedJob
	for _, j := range d.managedJobs(c) {
		jobs = append(jobs, installedJob{Domain: "system", Label: j.Label, Path: j.Path(), Program: j.Program()})
	}
	return jobs
}

func (d *Deployer) waitUnified(c service.Config, previous int64, started time.Time) error {
	if d.acceptUnified != nil {
		return d.acceptUnified(d.layout(c).Config, previous)
	}
	for attempt := 0; attempt < 90; attempt++ {
		ready := true
		for _, job := range d.unifiedJobs(c) {
			out, err := d.Run("/bin/launchctl", "print", job.Domain+"/"+job.Label)
			if err != nil {
				ready = false
				break
			}
			info := service.ParseLaunch(out)
			if info.Program != job.Program || info.Path != job.Path {
				ready = false
				break
			}
			switch job.Label {
			case "homebrew.mxcl.dnsmasq", "com.local.network-domain-proxy", "com.local.network-split-dns-event-route-agent":
				if info.State != "running" || info.PID <= 0 {
					ready = false
				}
			default:
				if info.State != "not running" || info.Exit != "0" {
					ready = false
				}
			}
		}
		if ready {
			if err := d.acceptHealthSample(previous); err != nil {
				return err
			}
			if err := acceptStatusPage(c, started); err != nil {
				return err
			}
			return d.health(ProxyPort)
		}
		if err := d.checkInterrupted(); err != nil {
			return err
		}
		d.Sleep(2 * time.Second)
	}
	return errors.New("unified workers did not become ready")
}

func acceptStatusPage(c service.Config, since time.Time) error {
	root, err := os.OpenRoot(c.Status.Home)
	if err != nil {
		return err
	}
	defer root.Close()
	path, err := filepath.Rel(c.Status.Home, c.Status.Output)
	if err != nil {
		return err
	}
	info, err := root.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 || !info.ModTime().After(since) {
		return errors.New("status worker did not publish a fresh page")
	}
	home, err := root.Stat(".")
	if err != nil || info.Sys().(*syscall.Stat_t).Uid != home.Sys().(*syscall.Stat_t).Uid || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return errors.New("status page ownership is invalid")
	}
	file, err := root.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return errors.New("status page changed during acceptance")
	}
	data, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
	if err != nil || len(data) > 4<<20 || !strings.Contains(string(data), `class="status OK"`) {
		return errors.New("fresh status page did not report OK")
	}
	return nil
}

func (d *Deployer) retiredPrograms(c service.Config) []string {
	layout := d.layout(c)
	paths := []string{layout.OldStatus}
	for _, name := range []string{"network-domain-proxy-deploy", "network-split-policy", "network-split-health", "network-split-dns-event-route-agent", "network-split-guard.sh", "china-route.sh"} {
		paths = append(paths, filepath.Join(layout.Sbin, name))
	}
	return paths
}

func (d *Deployer) unifiedTargets(c service.Config, legacy bool) []string {
	layout := d.layout(c)
	targets := []string{d.Binary, layout.Config, layout.MainPlist, layout.Newsyslog}
	for _, job := range d.managedJobs(c) {
		targets = append(targets, job.Path())
	}
	if legacy {
		for _, job := range d.legacyJobs(c, "") {
			targets = append(targets, job.Path)
		}
		targets = append(targets, d.retiredPrograms(c)...)
	}
	slices.Sort(targets)
	return slices.Compact(targets)
}

// Consolidate keeps the current proxy configuration, rule cache and DNS data.
// Only program and launchd ownership change. A failed activation restores every
// saved file and the previously loaded job set before reporting failure.
func (d *Deployer) Consolidate(configPath string) (backup string, resultErr error) {
	c, err := service.Load(configPath, false)
	if err != nil {
		return "", err
	}
	if d.unifiedLayout == nil {
		if err := service.CheckInstallation(c); err != nil {
			return "", err
		}
	}
	account, err := user.Lookup(c.Status.User)
	if err != nil {
		return "", err
	}
	layout := d.layout(c)
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return "", err
	}
	userFiles, err := openUserFiles(layout.UserHome, uint32(uid), layout.UserPlist, layout.OldStatus)
	if err != nil {
		return "", err
	}
	d.userFiles = userFiles
	defer func() { userFiles.root.Close(); d.userFiles = nil }()
	var existing map[string]any
	data, err := os.ReadFile(d.Config)
	if err != nil {
		return "", err
	}
	if err = json.Unmarshal(data, &existing); err != nil {
		return "", err
	}
	sources, ok := existing["rule_sources"].([]any)
	if !ok || len(sources) != 3 {
		return "", errors.New("installed rule sources are invalid")
	}
	kinds := make(map[string]bool)
	for _, source := range sources {
		m, ok := source.(map[string]any)
		if !ok {
			return "", errors.New("installed rule source is invalid")
		}
		kind, ok := m["kind"].(string)
		if !ok || !slices.Contains(RuleNames, kind) || kinds[kind] {
			return "", errors.New("installed rule kind is invalid")
		}
		kinds[kind] = true
	}
	for key, iface := range map[string]string{"domestic": c.Routes.WiredInterface, "foreign": c.Routes.WiFiInterface} {
		value, ok := existing[key].(map[string]any)
		if !ok || value["interface"] != iface {
			return "", errors.New("proxy and route interfaces differ")
		}
	}
	if err := d.preflight(existing); err != nil {
		return "", err
	}
	if d.preflightOnly {
		fmt.Fprintln(d.Out, "Unified candidate preflight accepted; installed services unchanged")
		return "", nil
	}
	oldUnified := false
	if _, err := os.Lstat(layout.MainPlist); err == nil {
		oldUnified = true
	} else if !os.IsNotExist(err) {
		return "", err
	}
	oldJobs := d.legacyJobs(c, account.Uid)
	parent := installedJob{Domain: "system", Label: service.Label, Path: layout.MainPlist, Program: d.Binary}
	if oldUnified {
		old, err := service.Load(layout.Config, d.unifiedLayout == nil)
		if err != nil || old != c {
			return "", errors.New("upgrade must preserve the installed service configuration")
		}
		oldJobs = d.unifiedJobs(c)
		oldJobs = append(oldJobs, parent)
	}
	for i, job := range oldJobs {
		oldJobs[i], err = d.inspectInstalledJob(job)
		if err != nil {
			return "", err
		}
	}
	jobs := d.managedJobs(c)
	legacyFiles := d.retiredPrograms(c)
	targets := d.unifiedTargets(c, !oldUnified)
	backup, err = os.MkdirTemp(d.BackupParent, "network-unified-backup.")
	if err != nil {
		return "", err
	}
	fmt.Fprintln(d.Out, "Unified rollback directory:", backup)
	records, err := d.snapshot(backup, targets)
	if err != nil {
		if cleanupErr := os.RemoveAll(backup); cleanupErr != nil {
			return backup, errors.Join(err, cleanupErr)
		}
		return "", err
	}
	changed, stopped := false, false
	var previousProbe int64
	var started time.Time
	err = func() error {
		if err := d.checkInterrupted(); err != nil {
			return err
		}
		stopped = true
		for i := len(oldJobs) - 1; i >= 0; i-- {
			if oldJobs[i].Loaded {
				if err := d.stopInstalledJob(oldJobs[i]); err != nil {
					return err
				}
			}
		}
		previousProbe, started = d.previousHealthProbe(), d.Now()
		if err := d.ensureDirectory(layout.Jobs, 0o755, "root"); err != nil {
			return err
		}
		changed = true
		if err := d.InstallFile(filepath.Join(d.Root, EngineName), d.Binary, 0o755); err != nil {
			return err
		}
		if err := d.InstallFile(configPath, layout.Config, 0o600); err != nil {
			return err
		}
		for i, job := range jobs {
			body, err := service.Plist(job.Definition)
			if err != nil {
				return err
			}
			source := filepath.Join(backup, fmt.Sprintf("job-%d.plist", i))
			if err := os.WriteFile(source, body, 0o600); err != nil {
				return err
			}
			if err := d.InstallFile(source, job.Path(), 0o644); err != nil {
				return err
			}
		}
		definition := service.MainDefinition()
		definition["ProgramArguments"] = []string{d.Binary, "service", "-c", layout.Config}
		body, err := service.Plist(definition)
		if err != nil {
			return err
		}
		source := filepath.Join(backup, "parent.plist")
		if err := os.WriteFile(source, body, 0o600); err != nil {
			return err
		}
		if err := d.InstallFile(source, layout.MainPlist, 0o644); err != nil {
			return err
		}
		if !oldUnified {
			for _, job := range oldJobs {
				remove := os.Remove
				if userFiles.has(job.Path) {
					remove = userFiles.remove
				}
				if err := remove(job.Path); err != nil && !os.IsNotExist(err) {
					return err
				}
			}
		}
		if err := d.extendUnifiedLogs(backup, layout.Newsyslog); err != nil {
			return err
		}
		if err := d.bootstrapJob(parent); err != nil {
			return err
		}
		if err := d.waitUnified(c, previousProbe, started); err != nil {
			return err
		}
		if !oldUnified {
			for _, path := range legacyFiles {
				var record *Record
				for i := range records {
					if records[i].Target == path {
						record = &records[i]
						break
					}
				}
				if record == nil || !record.Present {
					continue
				}
				before, err := fileDigest(filepath.Join(backup, record.Copy))
				if err != nil {
					return err
				}
				digest := fileDigest
				if userFiles.has(path) {
					digest = userFiles.digest
				}
				after, err := digest(path)
				if err != nil || before != after {
					return fmt.Errorf("retired file changed during migration: %s", path)
				}
				remove := os.Remove
				if userFiles.has(path) {
					remove = userFiles.remove
				}
				if err := remove(path); err != nil {
					return err
				}
			}
		}
		return d.checkInterrupted()
	}()
	if err == nil {
		fmt.Fprintln(d.Out, "Unified application accepted; legacy startup definitions and executables retired")
		return backup, nil
	}
	if !stopped {
		return backup, err
	}
	var rollback []error
	if changed {
		rollback = append(rollback, d.stopInstalledJob(parent))
		for i := len(jobs) - 1; i >= 0; i-- {
			j := jobs[i]
			rollback = append(rollback, d.stopInstalledJob(installedJob{Domain: "system", Label: j.Label, Path: j.Path(), Program: j.Program()}))
		}
		if stopErr := errors.Join(rollback...); stopErr != nil {
			return backup, fmt.Errorf("%w; new jobs could not be stopped for rollback: %v", err, stopErr)
		}
		if restoreErr := d.restore(backup, records); restoreErr != nil {
			return backup, fmt.Errorf("%w; file rollback failed: %v", err, restoreErr)
		}
	}
	rollback = nil
	for _, job := range oldJobs {
		if job.Loaded {
			current, checkErr := d.inspectInstalledJob(job)
			if checkErr != nil {
				rollback = append(rollback, checkErr)
				continue
			}
			if !current.Loaded {
				rollback = append(rollback, d.bootstrapJob(job))
			}
		}
	}
	if rollbackErr := errors.Join(rollback...); rollbackErr != nil {
		return backup, fmt.Errorf("%w; old job restoration failed: %v", err, rollbackErr)
	}
	return backup, err
}

func (d *Deployer) extendUnifiedLogs(backup, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	text := string(data)
	for _, name := range []string{"network-split-service.log", "network-split-service.out", "network-split-service.err", "network-split-status.out", "network-split-status.err", "china-route.out", "china-route.err"} {
		full := "/var/log/" + name
		present := false
		for _, line := range strings.Split(text, "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == full {
				present = true
				break
			}
		}
		if !present {
			text += "\n" + full + " root:wheel 644 3 256 * N\n"
		}
	}
	source := filepath.Join(backup, "newsyslog.conf")
	if err := os.WriteFile(source, []byte(text), 0o600); err != nil {
		return err
	}
	return d.InstallFile(source, path, 0o644)
}

func Consolidate(ctx context.Context, root, config string, out *os.File, preflightOnly bool) (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("consolidation requires administrator authorization")
	}
	d := New(Production, root, out)
	d.Run = func(args ...string) (string, error) {
		limit := 30 * time.Second
		if slices.Equal(args, []string{"/bin/launchctl", "bootout", "system/" + service.Label}) {
			limit = (service.ParentExitTimeout + 15) * time.Second
		}
		// Rollback must still be able to invoke launchctl after cancellation.
		return runtimecheck.RunContext(context.Background(), limit, args...)
	}
	d.preflightOnly = preflightOnly
	d.Context = ctx
	d.Interrupted = func() bool { return ctx.Err() != nil }
	release, err := d.Lock()
	if err != nil {
		return "", err
	}
	defer release()
	return d.Consolidate(config)
}
