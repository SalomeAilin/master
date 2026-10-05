package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"network-owned-engine/internal/healthcheck"
	"network-owned-engine/internal/service"
	"network-owned-engine/internal/statuspage"
)

func retryable(err error) bool { var r *retryableAcceptance; return errors.As(err, &r) }

func TestAcceptanceRetryLimitAndCancellation(t *testing.T) {
	for _, kind := range []string{"recover", "exhaust", "fatal", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			d := maintenanceFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			d.Context = ctx
			calls, sleeps := 0, 0
			d.Sleep = func(time.Duration) { sleeps++ }
			err := d.acceptanceRounds(func(attempt int) error {
				if attempt != calls {
					t.Fatal(attempt, calls)
				}
				calls++
				switch kind {
				case "fatal":
					return os.ErrPermission
				case "cancel":
					cancel()
				case "recover":
					if calls == 3 {
						return nil
					}
				}
				return &retryableAcceptance{errors.New("network unavailable")}
			})
			if (err == nil) != (kind == "recover") {
				t.Fatal(err)
			}
			if kind == "recover" || kind == "exhaust" {
				if calls != 3 || sleeps != 2 {
					t.Fatal(calls, sleeps)
				}
			} else if calls != 1 || sleeps != 0 {
				t.Fatal("fatal failure retried", calls, sleeps)
			}
			if d.Context != ctx {
				t.Fatal("deadline leaked into rollback")
			}
		})
	}
}

func TestOnlyNetworkStatusFailuresAreRetryable(t *testing.T) {
	for _, kind := range []string{"dns", "http", "permissions", "route", "private-address", "negative-dns", "inconsistent"} {
		s := statuspage.Snapshot{State: "BAD", Checks: []statuspage.Row{{Name: "dns-security-baseline", State: "ok"}}, Domains: []statuspage.Row{{Name: "example.test", State: "unknown", Detail: "DNS lookup failed"}}}
		switch kind {
		case "http":
			s.Domains[0].State = "wired"
			s.Checks = append(s.Checks, statuspage.Row{Name: "https://claude.ai/", State: "bad"})
		case "permissions":
			s.Checks[0].State = "bad"
		case "route":
			s.Domains[0].State = "drift"
		case "private-address":
			s.Domains[0].State = "bad"
		case "negative-dns":
			s.Checks = append(s.Checks, statuspage.Row{Name: "negative-dns", State: "bad"})
		case "inconsistent":
			s.State = "OK"
		}
		err := statusAcceptance(s)
		if err == nil || retryable(err) != (kind == "dns" || kind == "http") {
			t.Fatal(kind, err)
		}
	}
	for _, code := range []int{7, 22, 28, 35, 52, 56, 60, 77, 2, 126} {
		err := retryableHTTP(&CommandError{Code: code})
		want := code == 7 || code == 22 || code == 28 || code == 35 || code == 52 || code == 56
		if retryable(err) != want {
			t.Fatal(code, err)
		}
	}
	if !retryable(retryableProbe(&net.OpError{Op: "read", Err: os.ErrDeadlineExceeded})) || retryable(retryableProbe(os.ErrPermission)) {
		t.Fatal("DNS retry classification")
	}
}

func TestEveryAcceptanceRetryRefreshesAndRepeatsAllChecks(t *testing.T) {
	for _, mutateFile := range []bool{false, true} {
		t.Run(fmt.Sprint(mutateFile), func(t *testing.T) {
			d, f := unifiedSetup(t)
			if _, err := d.Consolidate(f.path); err != nil {
				t.Fatal(err)
			}
			d.acceptUnified = nil
			c := f.config
			c.Version = 2
			c.Routes.DNSBinary = service.Binary
			c.Status.Home = t.TempDir()
			c.Status.State = filepath.Join(c.Status.Home, "state")
			c.Status.Output = filepath.Join(c.Status.Home, "status.html")
			for _, job := range d.managedJobs(c) {
				body, err := service.Plist(job.Definition)
				if err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, job.Path(), string(body))
			}
			now := time.Now()
			d.Now = func() time.Time { return now }
			publish := func() {
				at := now.Add(time.Millisecond)
				s := statuspage.Snapshot{State: "OK", Checked: at, Published: at, HTMLPath: c.Status.Output, HTMLBytes: 1, HTMLSHA256: strings.Repeat("a", 64), Checks: []statuspage.Row{{State: "ok"}}, Domains: []statuspage.Row{{State: "wired"}}}
				body, _ := json.Marshal(s)
				writeTestFile(t, c.Status.State, string(body))
				if err := os.Chtimes(c.Status.State, at, at); err != nil {
					t.Fatal(err)
				}
			}
			publish()
			health := healthcheck.State{Interval: 30, LastProbe: now.Unix() - 1}
			writeHealth := func() { writeTestFile(t, filepath.Join(d.BackupParent, healthState), string(health.Encode())) }
			writeHealth()
			d.Sleep = func(duration time.Duration) { now = now.Add(duration); health.LastProbe = now.Unix(); writeHealth() }
			d.Dial = func(string, time.Duration) (io.Closer, error) { return closer{}, nil }
			refreshes, dnsChecks, domesticHTTP, foreignHTTP := 0, 0, 0, 0
			d.probeDNS = func(address string) error {
				if address != "127.0.0.1:53" && address != c.Routes.DNS+":53" {
					t.Fatal(address)
				}
				dnsChecks++
				return nil
			}
			d.Run = func(args ...string) (string, error) {
				if args[0] == "/usr/bin/curl" {
					if args[len(args)-1] == "https://www.douyin.com/" {
						domesticHTTP++
						return "", nil
					}
					foreignHTTP++
					if foreignHTTP < 3 {
						if mutateFile {
							writeTestFile(t, d.Config, "changed")
						}
						return "", &CommandError{Code: 22}
					}
					return "", nil
				}
				if args[0] != "/bin/launchctl" {
					t.Fatal(args)
				}
				if args[1] == "kickstart" {
					if len(args) != 3 || args[2] != "system/com.local.network-split-log-guard" {
						t.Fatal("unexpected restart", args)
					}
					refreshes++
					publish()
					return "", nil
				}
				if args[1] != "print" {
					t.Fatal("unexpected mutation", args)
				}
				if args[2] == "system/"+service.Label {
					return fmt.Sprintf("state = running\nprogram = %s\npid = 123\n", d.Binary), nil
				}
				for _, job := range d.managedJobs(c) {
					if args[2] != "system/"+job.Label {
						continue
					}
					state, pid := "not running", 0
					if job.Label == service.NativeDNSLabel || job.Label == "com.local.network-domain-proxy" || job.Label == "com.local.network-split-dns-event-route-agent" {
						state, pid = "running", 123
					}
					return fmt.Sprintf("path = %s\nprogram = %s\narguments = {\n%s\n}\nstate = %s\npid = %d\nlast exit code = 0\n", job.Path(), job.Program(), strings.Join(job.Arguments(), "\n"), state, pid), nil
				}
				t.Fatal(args)
				return "", nil
			}
			err := d.waitUnified(c, health.LastProbe, now.Add(-time.Second))
			if mutateFile {
				if err == nil || retryable(err) || foreignHTTP != 1 || refreshes != 0 {
					t.Fatal("file change retried", err, foreignHTTP, refreshes)
				}
			} else if err != nil || refreshes != 2 || dnsChecks != 6 || domesticHTTP != 3 || foreignHTTP != 3 {
				t.Fatal("partial retry", err, refreshes, dnsChecks, domesticHTTP, foreignHTTP)
			}
		})
	}
}

func TestFreshReceiptWaitNeverRetriesInvalidMetadata(t *testing.T) {
	d := maintenanceFixture(t)
	home := t.TempDir()
	c := service.Config{Status: service.StatusConfig{Home: home, State: filepath.Join(home, "state"), Output: filepath.Join(home, "page")}}
	start := time.Now()
	s := statuspage.Snapshot{State: "OK", Checked: start.Add(-time.Second), Published: start.Add(-time.Second), HTMLPath: c.Status.Output, HTMLBytes: 1, HTMLSHA256: strings.Repeat("a", 64), Checks: []statuspage.Row{{State: "ok"}}, Domains: []statuspage.Row{{State: "wired"}}}
	write := func() { b, _ := json.Marshal(s); writeTestFile(t, c.Status.State, string(b)) }
	write()
	waits := 0
	d.Sleep = func(time.Duration) { waits++; s.Checked, s.Published = time.Now(), time.Now(); write() }
	if err := d.waitStatusReport(c, start); err != nil || waits != 1 {
		t.Fatal(err, waits)
	}
	if err := os.Chmod(c.Status.State, 0o666); err != nil {
		t.Fatal(err)
	}
	d.Sleep = func(time.Duration) { t.Fatal("unsafe file was retried") }
	if err := d.waitStatusReport(c, start); err == nil || retryable(err) {
		t.Fatal(err)
	}
}
