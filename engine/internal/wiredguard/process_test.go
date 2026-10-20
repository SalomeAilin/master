package wiredguard

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"syscall"
	"testing"
)

func ordinaryKernelProcess() kernelProcess {
	return kernelProcess{Identity: Identity{PID: 80, Started: 500, UID: 501, GID: 20, RealGID: 20, SavedGID: 20}, Comm: "ordinary-helper"}
}

func missingPathOperations(p kernelProcess, keys []SocketKey) snapshotOperations {
	return snapshotOperations{
		list: func() ([]kernelProcess, error) { return []kernelProcess{p}, nil },
		identity: func(pid int) (Identity, error) {
			return Identity{}, &pathUnavailableError{PID: pid, Err: syscall.ENOENT}
		},
		sockets: func(int) ([]SocketKey, error) { return keys, nil },
		current: func(int) (kernelProcess, error) { return p, nil },
		gone:    func(int) bool { return false },
	}
}

func TestUnavailableExecutablePathIsNotProcessExit(t *testing.T) {
	p := ordinaryKernelProcess()
	current := func(int) (kernelProcess, error) { return p, nil }
	path := func(int) (string, error) { return "", syscall.ENOENT }
	identity, err := readProcessIdentity(p.Identity.PID, current, path, func(int) bool { return false })
	var unavailable *pathUnavailableError
	if err == nil || identity != (Identity{}) || !errors.As(err, &unavailable) || unavailable.PID != p.Identity.PID {
		t.Fatal("strict identity lookup accepted an unavailable path", identity, err)
	}
	for _, candidate := range []error{err, fmt.Errorf("identity lookup: %w", err)} {
		if os.IsNotExist(candidate) || errors.Is(candidate, os.ErrNotExist) || errors.Is(candidate, syscall.ENOENT) {
			t.Fatal("live process path failure can be mistaken for an exit", candidate)
		}
	}
	_, err = readProcessIdentity(p.Identity.PID, current, path, func(int) bool { return true })
	if !os.IsNotExist(err) {
		t.Fatal("verified exit was not distinguished from path unavailability", err)
	}
}

func TestOrdinaryMissingPathStillScansAllDescriptorsAndPreventsRelease(t *testing.T) {
	p := ordinaryKernelProcess()
	other := p
	other.Identity.PID, other.Identity.UID = 81, 502
	key := testSocket().Key
	operations := missingPathOperations(p, []SocketKey{key})
	operations.list = func() ([]kernelProcess, error) { return []kernelProcess{p, other}, nil }
	operations.current = func(pid int) (kernelProcess, error) {
		if pid == other.Identity.PID {
			return other, nil
		}
		return p, nil
	}
	var scanned []int
	operations.sockets = func(pid int) ([]SocketKey, error) {
		scanned = append(scanned, pid)
		return []SocketKey{key}, nil
	}
	snap, err := processSnapshot(context.Background(), p.Identity.UID, nil, operations)
	if err != nil || len(snap.Processes) != 1 || snap.Processes[0] != p.Identity || len(snap.UnresolvedPaths) != 1 || snap.UnresolvedPaths[0].Process.Path != "" || len(snap.Sockets) != 2 || !slices.Equal(scanned, []int{80, 81}) {
		t.Fatal("path fallback omitted an unknown holder or its descriptors", snap, scanned, err)
	}
	s := activeState()
	s.SeenSockets = []SocketKey{key}
	counts, err := CountSockets(s, snap)
	if err != nil || counts.Controlled != 0 || counts.Observed != 1 || counts.Remaining != 1 {
		t.Fatal("cross-PID observed socket disappeared from accounting", counts, err)
	}
	f := &fakeSystem{snapshot: snap, barrier: true, token: true}
	if err = (Controller{System: f}).Release(context.Background(), &s); err == nil || !f.barrier || slices.Contains(f.events, "clear") || len(s.SeenSockets) != 1 {
		t.Fatal("unknown-path holder allowed premature release", f.events, s, err)
	}
}

func TestMissingPathRefusesProtectedProcessesAndOtherErrors(t *testing.T) {
	for name, change := range map[string]func(*kernelProcess, *State){
		"baidu comm":          func(p *kernelProcess, _ *State) { p.Comm = "BaiduNetdisk He" },
		"netdisk comm":        func(p *kernelProcess, _ *State) { p.Comm = "netdisk_service" },
		"effective reserved":  func(p *kernelProcess, _ *State) { p.Identity.GID = 62000 },
		"real reserved upper": func(p *kernelProcess, _ *State) { p.Identity.RealGID = 62127 },
		"saved reserved":      func(p *kernelProcess, _ *State) { p.Identity.SavedGID = 62050 },
		"other UID reserved":  func(p *kernelProcess, _ *State) { p.Identity.UID, p.Identity.GID = 502, 62001 },
		"recorded app":        func(p *kernelProcess, s *State) { s.App = &p.Identity },
		"recorded proxy":      func(p *kernelProcess, s *State) { s.Proxy = &p.Identity },
		"recorded launcher":   func(p *kernelProcess, s *State) { s.Launcher = &p.Identity },
	} {
		t.Run(name, func(t *testing.T) {
			p, state := ordinaryKernelProcess(), freshState()
			change(&p, &state)
			operations := missingPathOperations(p, nil)
			operations.sockets = func(int) ([]SocketKey, error) {
				t.Fatal("protected path failure reached descriptor scan")
				return nil, nil
			}
			if snap, err := processSnapshot(context.Background(), 501, &state, operations); err == nil || len(snap.UnresolvedPaths) != 0 {
				t.Fatal("protected process used ordinary path fallback", snap, err)
			}
		})
	}
	for _, errno := range []error{syscall.EPERM, syscall.EACCES, syscall.EIO, errors.New("unknown path failure"), fmt.Errorf("not an exact errno: %w", syscall.ENOENT)} {
		operations := missingPathOperations(ordinaryKernelProcess(), nil)
		operations.identity = func(pid int) (Identity, error) { return Identity{}, &pathUnavailableError{PID: pid, Err: errno} }
		if _, err := processSnapshot(context.Background(), 501, nil, operations); err == nil {
			t.Fatal("non-ENOENT path error was ignored", errno)
		}
	}
}

func TestMissingPathRequiresStableFreshClassificationAndCompleteFDScan(t *testing.T) {
	for _, moment := range []int{1, 2} {
		for name, change := range map[string]func(*kernelProcess){
			"comm":          func(p *kernelProcess) { p.Comm = "another-helper" },
			"baidu comm":    func(p *kernelProcess) { p.Comm = "baidunetdiskhost" },
			"effective gid": func(p *kernelProcess) { p.Identity.GID = 62000 },
			"real gid":      func(p *kernelProcess) { p.Identity.RealGID++ },
			"saved gid":     func(p *kernelProcess) { p.Identity.SavedGID++ },
			"uid":           func(p *kernelProcess) { p.Identity.UID++ },
			"start":         func(p *kernelProcess) { p.Identity.Started++ },
		} {
			t.Run(fmt.Sprintf("%d-%s", moment, name), func(t *testing.T) {
				p, calls := ordinaryKernelProcess(), 0
				operations := missingPathOperations(p, []SocketKey{testSocket().Key})
				operations.current = func(int) (kernelProcess, error) {
					calls++
					current := p
					if calls == moment {
						change(&current)
					}
					return current, nil
				}
				if _, err := processSnapshot(context.Background(), 501, nil, operations); err == nil {
					t.Fatal("classification change was ignored")
				}
			})
		}
	}
	p := ordinaryKernelProcess()
	operations := missingPathOperations(p, nil)
	operations.sockets = func(int) ([]SocketKey, error) { return nil, syscall.EPERM }
	if _, err := processSnapshot(context.Background(), 501, nil, operations); !errors.Is(err, syscall.EPERM) {
		t.Fatal("path fallback hid an incomplete descriptor scan", err)
	}
}
