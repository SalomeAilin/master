package wiredguard

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestEvidenceRechecksIdentityAndBarrierAndPreservesRawSamples(t *testing.T) {
	for _, failure := range []string{"", "before-identity", "before-barrier", "sample", "log", "after-identity", "after-barrier"} {
		t.Run(failure, func(t *testing.T) {
			state := activeState()
			state.Cache = "/private/tmp/network-domain-wired-app.test"
			identityCalls, barrierCalls, sampleCalls := 0, 0, 0
			const csv = "time,interface,bytes_in,bytes_out\nexternal,en7,100,20\nother,en8,1,2\n"
			const log = "{\"event\":\"connected\",\"id\":1}\n"
			operations := evidenceOperations{
				identity: func(pid int) (Identity, error) {
					identityCalls++
					if pid != state.Proxy.PID {
						t.Fatal("wrong proxy PID", pid)
					}
					identity := *state.Proxy
					if (failure == "before-identity" && identityCalls == 1) || (failure == "after-identity" && identityCalls == 2) {
						identity.Started++ // The PID has been reused.
					}
					return identity, nil
				},
				verify: func(context.Context, State) error {
					barrierCalls++
					if (failure == "before-barrier" && barrierCalls == 1) || (failure == "after-barrier" && barrierCalls == 2) {
						return errors.New("barrier changed")
					}
					return nil
				},
				command: func(ctx context.Context, input string, args ...string) (string, error) {
					sampleCalls++
					want := []string{"/usr/bin/nettop", "-n", "-x", "-p", "20", "-L", "3", "-s", "2"}
					if input != "" || !slices.Equal(args, want) {
						t.Fatal("unexpected sample command", input, args)
					}
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) > 15*time.Second {
						t.Fatal("sample has no bounded deadline")
					}
					if failure == "sample" {
						return csv, errors.New("sample failed")
					}
					return csv, nil
				},
				log: func(path string, parentUID, workerUID uint32) (string, error) {
					if path != state.Cache || parentUID != 0 || workerUID != state.Proxy.UID {
						t.Fatal("wrong private log ownership", path, parentUID, workerUID)
					}
					if failure == "log" {
						return "", errors.New("unsafe log")
					}
					return log, nil
				},
			}
			report, err := collectEvidence(context.Background(), state, operations)
			if failure == "" {
				if err != nil || report.NettopCSV != csv || report.RecentLog != log || !report.BarrierVerified || !report.ProxyIdentityVerified || report.Finished.Before(report.Started) {
					t.Fatal(report, err)
				}
			} else if err == nil || report.NettopCSV != "" || report.RecentLog != "" || report.BarrierVerified || report.ProxyIdentityVerified {
				t.Fatal("failed observation returned verified data", report, err)
			}
			if strings.HasPrefix(failure, "before-") {
				if sampleCalls != 0 || identityCalls != 1 || barrierCalls != 1 {
					t.Fatal("unsafe initial state was sampled", sampleCalls, identityCalls, barrierCalls)
				}
			} else if sampleCalls != 1 || identityCalls != 2 || barrierCalls != 2 {
				t.Fatal("post-sample verification missing", sampleCalls, identityCalls, barrierCalls)
			}
		})
	}
}

func TestRecentProxyLogIsBoundedAndRejectsUnsafePaths(t *testing.T) {
	for _, kind := range []string{"valid", "tail", "parent-symlink", "worker-symlink", "log-symlink", "fifo", "hardlink", "parent-mode", "worker-mode", "log-mode", "parent-owner", "worker-owner"} {
		t.Run(kind, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "cache")
			worker := filepath.Join(root, "worker")
			if err := os.Mkdir(root, 0711); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(root, 0711); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(worker, 0700); err != nil {
				t.Fatal(err)
			}
			path, content := filepath.Join(worker, "proxy.log"), "recent private log\n"
			if kind == "tail" {
				content = "excluded prefix" + strings.Repeat("x", recentProxyLogLimit)
			}
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			uid := uint32(os.Geteuid())
			parentUID, workerUID := uid, uid
			var err error
			switch kind {
			case "parent-symlink", "worker-symlink", "log-symlink":
				from := map[string]string{"parent-symlink": root, "worker-symlink": worker, "log-symlink": path}[kind]
				err = os.Rename(from, from+".original")
				if err == nil {
					err = os.Symlink(from+".original", from)
				}
			case "fifo":
				err = os.Remove(path)
				if err == nil {
					err = unix.Mkfifo(path, 0600)
				}
			case "hardlink":
				err = os.Link(path, filepath.Join(worker, "other"))
			case "parent-mode":
				err = os.Chmod(root, 0777)
			case "worker-mode":
				err = os.Chmod(worker, 0755)
			case "log-mode":
				err = os.Chmod(path, 0644)
			case "parent-owner":
				parentUID++
			case "worker-owner":
				workerUID++
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := readRecentProxyLog(root, parentUID, workerUID)
			if kind == "valid" || kind == "tail" {
				want := content[max(0, len(content)-recentProxyLogLimit):]
				if err != nil || got != want {
					t.Fatal("wrong bounded log content", len(got), err)
				}
			} else if err == nil || got != "" {
				t.Fatal("unsafe private log accepted", kind, err)
			}
		})
	}
}
