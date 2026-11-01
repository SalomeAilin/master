package wiredguard

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

func validBootID(id string) bool {
	return regexp.MustCompile(`^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$`).MatchString(id)
}

type rebootRecoveryOps struct {
	boot    func() (string, int64, error)
	pf      func(context.Context, State) error
	inspect func(context.Context) (Snapshot, error)
	archive func() (string, error)
}

// Legacy records lack a boot UUID. Their complete recorded process identities
// must predate the current boot by a wide margin; this is a wall-clock check,
// so it is only used by an explicitly requested administrative recovery.
func previousBoot(s State, bootID string, bootMicros int64) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if !validBootID(bootID) || bootMicros <= 0 {
		return errors.New("current boot identity is unavailable")
	}
	if s.BootID != "" {
		if s.BootID == bootID {
			return errors.New("session belongs to the current boot")
		}
		return nil
	}
	if s.Proxy == nil || s.App == nil || s.Launcher == nil || s.LaunchPending {
		return errors.New("legacy session lacks complete process identities; manual inspection required")
	}
	for _, p := range []*Identity{s.Proxy, s.App, s.Launcher} {
		if p.Started <= 0 || p.Started >= bootMicros-300000000 {
			return errors.New("legacy process timestamps do not establish an earlier boot")
		}
	}
	return nil
}

func emptyAfterReboot(s State, snap Snapshot) error {
	for _, p := range snap.Processes {
		if IsBaidu(p) || reservedProcess(p) {
			return errors.New("Baidu or a reserved-GID process is still present")
		}
		for _, old := range []*Identity{s.Proxy, s.App, s.Launcher} {
			if old != nil && SameProcess(p, *old) {
				return errors.New("a recorded session process is still present")
			}
		}
	}
	for _, socket := range snap.Sockets {
		if reservedProcess(socket.Holder) {
			return errors.New("a reserved-GID socket is still held")
		}
	}
	counts, err := CountSockets(s, snap)
	if err != nil {
		return err
	}
	if counts.Remaining != 0 {
		return errors.New("a controlled or previously observed socket is still held")
	}
	return nil
}

// This path archives only the old userspace record. It never clears an anchor,
// signals a PID, deletes a cache, or releases an old token in the new kernel.
func recoverReboot(ctx context.Context, s State, ops rebootRecoveryOps) (string, error) {
	bootID, bootTime, err := ops.boot()
	if err != nil {
		return "", err
	}
	if err = previousBoot(s, bootID, bootTime); err != nil {
		return "", err
	}
	for range 2 {
		if err = ctx.Err(); err != nil {
			return "", err
		}
		if err = ops.pf(ctx, s); err != nil {
			return "", err
		}
		snap, e := ops.inspect(ctx)
		if e != nil {
			return "", e
		}
		if e = emptyAfterReboot(s, snap); e != nil {
			return "", e
		}
	}
	lastID, lastTime, err := ops.boot()
	if err != nil || lastID != bootID || lastTime != bootTime {
		return "", errors.New("boot identity changed or became unavailable during inspection")
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	return ops.archive()
}

func (n *Native) recoverReboot(ctx context.Context, s State) (string, error) {
	return recoverReboot(ctx, s, rebootRecoveryOps{
		boot: bootIdentity,
		pf: func(ctx context.Context, s State) error {
			p, err := n.pfSnapshot(ctx)
			if err != nil {
				return err
			}
			return validateRebootPF(p, s)
		},
		inspect: func(ctx context.Context) (Snapshot, error) { return n.Inspect(ctx, nil) },
		archive: n.Store.Archive,
	})
}

func validateRebootPF(p PFSnapshot, s State) error {
	p.Wired = s.Wired
	if strings.TrimSpace(p.Filters[Anchor]) != "" || strings.TrimSpace(p.Translations[Anchor]) != "" {
		return errors.New("private PF anchor is not empty; reboot recovery refused")
	}
	if err := ValidatePF(p, ""); err != nil {
		return fmt.Errorf("current PF configuration cannot be verified: %w", err)
	}
	return nil
}
