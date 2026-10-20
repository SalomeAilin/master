package wiredguard

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// A live process can outlast its executable's directory entry. This error does
// not unwrap ENOENT: callers must not mistake an unavailable path for an exit.
type pathUnavailableError struct {
	PID int
	Err error
}

func (e *pathUnavailableError) Error() string {
	return fmt.Sprintf("cannot identify executable path for live process %d: %v", e.PID, e.Err)
}

type UnresolvedPath struct {
	Process    Identity `json:"process"`
	KernelName string   `json:"kernel_name"`
	Reason     string   `json:"reason"`
}

type kernelProcess struct {
	Identity Identity
	Comm     string
	Zombie   bool
}

type snapshotOperations struct {
	list     func() ([]kernelProcess, error)
	identity func(int) (Identity, error)
	sockets  func(int) ([]SocketKey, error)
	current  func(int) (kernelProcess, error)
	gone     func(int) bool
}

func reservedProcess(p Identity) bool {
	for _, gid := range []uint32{p.GID, p.RealGID, p.SavedGID} {
		if gid >= 62000 && gid <= 62127 {
			return true
		}
	}
	return false
}

func protectedProcess(p kernelProcess, s *State) bool {
	name := strings.ToLower(p.Comm)
	if reservedProcess(p.Identity) || strings.Contains(name, "baidu") || strings.Contains(name, "netdisk") {
		return true
	}
	if s != nil {
		for _, known := range []*Identity{s.App, s.Proxy, s.Launcher} {
			if known != nil && known.PID == p.Identity.PID {
				return true
			}
		}
	}
	return false
}

func ordinaryPathFallback(p kernelProcess, uid uint32, s *State) bool {
	return p.Identity.UID == uid && !protectedProcess(p, s)
}

func readProcessIdentity(pid int, current func(int) (kernelProcess, error), path func(int) (string, error), gone func(int) bool) (Identity, error) {
	p, err := current(pid)
	if err != nil {
		if gone(pid) {
			return Identity{}, os.ErrNotExist
		}
		return Identity{}, err
	}
	if p.Zombie {
		return Identity{}, os.ErrNotExist
	}
	executable, err := path(pid)
	if err != nil {
		if gone(pid) {
			return Identity{}, os.ErrNotExist
		}
		return Identity{}, &pathUnavailableError{PID: pid, Err: err}
	}
	p.Identity.Path = executable
	return p.Identity, nil
}

func processSnapshot(ctx context.Context, uid uint32, state *State, operations snapshotOperations) (Snapshot, error) {
	var result Snapshot
	processes, err := operations.list()
	if err != nil {
		return result, err
	}
	if len(processes) > 32768 {
		return result, errors.New("process inventory exceeds limit")
	}
	for _, process := range processes {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		holder := process.Identity
		if holder.PID <= 0 || process.Zombie {
			continue
		}
		include := holder.UID == uid || protectedProcess(process, state)
		identity, unresolved := holder, false
		if include {
			identity, err = operations.identity(holder.PID)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				var unavailable *pathUnavailableError
				if !ordinaryPathFallback(process, uid, state) || !errors.As(err, &unavailable) || unavailable.PID != holder.PID {
					return result, err
				}
				if errno, ok := unavailable.Err.(syscall.Errno); !ok || errno != syscall.ENOENT {
					return result, err
				}
				fresh, freshErr := operations.current(holder.PID)
				if freshErr != nil {
					if operations.gone(holder.PID) {
						continue
					}
					return result, freshErr
				}
				if fresh.Identity != holder || fresh.Comm != process.Comm || fresh.Zombie || !ordinaryPathFallback(fresh, uid, state) {
					return result, errors.New("unresolved process classification changed before socket scan")
				}
				identity, unresolved = holder, true
			} else {
				credentials := identity
				credentials.Path = ""
				if credentials != holder {
					return result, errors.New("process identity changed before socket scan")
				}
			}
		}
		// Every process still participates in the descriptor census, including
		// ordinary holders whose executable path cannot be classified.
		keys, socketErr := operations.sockets(holder.PID)
		if socketErr != nil {
			if operations.gone(holder.PID) {
				continue
			}
			return result, fmt.Errorf("cannot inspect socket ownership for process %d: %w", holder.PID, socketErr)
		}
		if len(keys) > 4096 || len(result.Sockets)+len(keys) > 65536 {
			return result, errors.New("socket inventory exceeds limit")
		}
		current, currentErr := operations.current(holder.PID)
		if currentErr != nil {
			if operations.gone(holder.PID) {
				continue
			}
			return result, currentErr
		}
		if current.Identity != holder {
			return result, errors.New("process identity changed during socket scan")
		}
		if unresolved && (current.Comm != process.Comm || current.Zombie || !ordinaryPathFallback(current, uid, state)) {
			return result, errors.New("unresolved process classification changed during socket scan")
		}
		if include {
			result.Processes = append(result.Processes, identity)
		}
		for _, key := range keys {
			result.Sockets = append(result.Sockets, Socket{Holder: holder, Key: key})
		}
		if unresolved {
			if len(result.UnresolvedPaths) == 128 {
				return result, errors.New("unresolved executable path inventory exceeds limit")
			}
			result.UnresolvedPaths = append(result.UnresolvedPaths, UnresolvedPath{Process: holder, KernelName: process.Comm, Reason: "proc_pidpath returned ENOENT; executable classification is unknown; socket descriptors were inspected"})
		}
	}
	return result, nil
}
