package wiredguard

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const oldBoot = "11111111-1111-1111-1111-111111111111"
const newBoot = "22222222-2222-2222-2222-222222222222"

func legacyRebootState() State {
	s := activeState()
	s.Phase = "held"
	launcher := Identity{PID: 40, Started: 102, Path: Binary}
	s.Launcher = &launcher
	return s
}

func TestPreviousBootEvidence(t *testing.T) {
	base := legacyRebootState()
	tests := []struct {
		name string
		s    State
		id   string
		time int64
		ok   bool
	}{
		{"legacy with all older identities", base, newBoot, 600000000, true},
		{"legacy before margin", base, newBoot, 300000101, false},
		{"malformed boot id", base, "bad", 600000000, false},
		{"invalid boot time", base, newBoot, 0, false},
		{"same boot", func() State { s := base; s.BootID = newBoot; return s }(), newBoot, 600000000, false},
		{"different boot uuid", func() State { s := base; s.BootID = oldBoot; return s }(), newBoot, 600000000, true},
		{"missing launcher", func() State { s := base; s.Launcher = nil; return s }(), newBoot, 600000000, false},
		{"unacknowledged launch", func() State { s := base; s.LaunchPending = true; return s }(), newBoot, 600000000, false},
		{"bad persisted uuid", func() State { s := base; s.BootID = "bad"; return s }(), newBoot, 600000000, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := previousBoot(tt.s, tt.id, tt.time); (err == nil) != tt.ok {
				t.Fatalf("previousBoot returned %v", err)
			}
		})
	}
}

func TestRebootRecoveryChecksBothSnapshotsAndNeverArchivesOnUncertainty(t *testing.T) {
	for _, failure := range []string{"", "boot", "pf-first", "pf-second", "scan-first", "scan-second", "baidu", "reserved", "reserved-socket", "observed-socket", "boot-changed", "archive"} {
		t.Run(failure, func(t *testing.T) {
			s := legacyRebootState()
			s.SeenSockets = []SocketKey{testSocket().Key}
			boots, pfs, scans, archives := 0, 0, 0, 0
			ops := rebootRecoveryOps{
				boot: func() (string, int64, error) {
					boots++
					if failure == "boot" {
						return "", 0, errors.New("boot")
					}
					if failure == "boot-changed" && boots == 2 {
						return oldBoot, 600000000, nil
					}
					return newBoot, 600000000, nil
				},
				pf: func(context.Context, State) error {
					pfs++
					if failure == "pf-first" && pfs == 1 || failure == "pf-second" && pfs == 2 {
						return errors.New("pf")
					}
					return nil
				},
				inspect: func(context.Context) (Snapshot, error) {
					scans++
					if failure == "scan-first" && scans == 1 || failure == "scan-second" && scans == 2 {
						return Snapshot{}, errors.New("scan")
					}
					if failure == "baidu" && scans == 2 {
						return Snapshot{Processes: []Identity{{Path: App, GID: 20}}}, nil
					}
					if failure == "reserved" && scans == 2 {
						return Snapshot{Processes: []Identity{{Path: "/other", RealGID: 62003}}}, nil
					}
					if failure == "reserved-socket" && scans == 2 {
						x := testSocket()
						x.Holder.RealGID = 62003
						return Snapshot{Sockets: []Socket{x}}, nil
					}
					if failure == "observed-socket" && scans == 2 {
						x := testSocket()
						x.Holder = Identity{PID: 99, Started: 500, UID: 501, GID: 20}
						return Snapshot{Sockets: []Socket{x}}, nil
					}
					return Snapshot{}, nil
				},
				archive: func() (string, error) {
					archives++
					if failure == "archive" {
						return "", errors.New("archive")
					}
					return "record", nil
				},
			}
			path, err := recoverReboot(context.Background(), s, ops)
			if failure == "" {
				if err != nil || path != "record" || pfs != 2 || scans != 2 || archives != 1 {
					t.Fatal(path, err, pfs, scans, archives)
				}
			} else if err == nil || (archives != 0 && failure != "archive") {
				t.Fatal("unsafe recovery accepted", path, err, archives)
			}
		})
	}
}

func TestRebootRecoveryRejectsUnexpectedPF(t *testing.T) {
	for name, mutate := range map[string]func(*PFSnapshot){
		"old anchor":     func(p *PFSnapshot) { p.Filters[Anchor] = "block all" },
		"translation":    func(p *PFSnapshot) { p.Translations[Anchor] = "rdr on lo0 all" },
		"foreign rules":  func(p *PFSnapshot) { p.Root = "pass all" },
		"existing state": func(p *PFSnapshot) { p.States = "unknown state" },
	} {
		t.Run(name, func(t *testing.T) {
			p := safePF()
			mutate(&p)
			if err := validateRebootPF(p, activeState()); err == nil {
				t.Fatal("unexpected PF configuration accepted")
			}
		})
	}
	if err := validateRebootPF(safePF(), activeState()); err != nil {
		t.Fatal(err)
	}
}

func TestArchivePreservesOriginalSession(t *testing.T) {
	store := testStore(t)
	s := legacyRebootState()
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(store.Path, "session.json"))
	if err != nil {
		t.Fatal(err)
	}
	path, err := store.Archive()
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatal("session archive differs", err)
	}
	if _, err := store.Read(); !os.IsNotExist(err) {
		t.Fatal("active record still present", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("archive permissions changed", err)
	}
}
