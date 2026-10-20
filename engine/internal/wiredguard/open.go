package wiredguard

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"syscall"
)

// Reopening never repairs an incomplete session or launches an ordinary app.
// The existing controller keeps its lock and remains responsible for cleanup.
func reuseSession(ctx context.Context, store Store, state State, uid uint32) error {
	pid, err := store.controllerPID()
	if err != nil {
		return err
	}
	controller, err := nativeIdentity(pid)
	if err != nil {
		return err
	}
	account, err := LookupAccount(uid)
	if err != nil {
		return err
	}
	native := &Native{Store: store, Account: account}
	snap, err := native.Inspect(ctx, &state)
	if err != nil {
		return err
	}
	if err = reusableSession(state, uid, controller, snap); err != nil {
		return err
	}
	if err = native.Verify(ctx, state); err != nil {
		return err
	}
	if err = proxyReady("127.0.0.1:17891"); err != nil {
		return err
	}
	latest, err := store.Read()
	if err != nil {
		return err
	}
	latestPID, err := store.controllerPID()
	if err != nil {
		return err
	}
	latestController, err := nativeIdentity(latestPID)
	if err != nil {
		return err
	}
	if !sameSession(state, latest) || !SameProcess(controller, latestController) {
		return errors.New("wired session changed during reopen; no application was launched")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"session": "reused", "app_pid": state.App.PID, "barrier_verified": true, "ordinary_launch_protected": false})
}

func reusableSession(s State, uid uint32, controller Identity, snap Snapshot) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if s.UID != uid || s.Phase != "active" || s.LaunchPending || !s.SocketObservationStarted || s.LastError != "" {
		return errors.New("existing wired session is not active for this user; inspect it before reopening")
	}
	if controller.PID <= 0 || controller.Started <= 0 || controller.Path != Binary || controller.UID != 0 || controller.GID != 0 || controller.RealGID != 0 || controller.SavedGID != 0 {
		return errors.New("wired session lock has no verified privileged controller")
	}
	for _, known := range []*Identity{s.App, s.Proxy, s.Launcher} {
		if known == nil || !slices.ContainsFunc(snap.Processes, func(p Identity) bool { return SameProcess(p, *known) }) {
			return errors.New("recorded wired application, proxy or GUI producer is no longer present")
		}
	}
	_, _, err := Ownership(s, snap)
	return err
}

// Socket observations can grow while reopening; stable launch identities and
// the barrier must still describe exactly the same session.
func sameSession(a, b State) bool {
	if a.UID != b.UID || a.GID != b.GID || a.Phase != b.Phase || a.Token != b.Token || a.RuleHash != b.RuleHash || a.Wired != b.Wired || a.Cache != b.Cache || a.LaunchPending != b.LaunchPending || a.SocketObservationStarted != b.SocketObservationStarted || a.LastError != b.LastError {
		return false
	}
	for _, pair := range [][2]*Identity{{a.App, b.App}, {a.Proxy, b.Proxy}, {a.Launcher, b.Launcher}} {
		if pair[0] == nil || pair[1] == nil || !SameProcess(*pair[0], *pair[1]) {
			return false
		}
	}
	return true
}

func (s Store) controllerPID() (int, error) {
	f, err := s.open("lock")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0}
	if err = syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &lock); err != nil {
		return 0, err
	}
	if lock.Type != syscall.F_WRLCK || lock.Pid <= 0 || lock.Start != 0 || lock.Len != 0 {
		return 0, errors.New("wired session has no live controller holding its complete lock")
	}
	return int(lock.Pid), nil
}
