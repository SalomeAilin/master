package wiredguard

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type fakeSystem struct {
	events         []string
	fail           string
	failed         bool
	saved          State
	barrier, token bool
	snapshot       Snapshot
	inspectCount   int
	late           Snapshot
	removed        bool
}

func (f *fakeSystem) step(name string) error {
	f.events = append(f.events, name)
	if f.fail == name && !f.failed {
		f.failed = true
		return errors.New("injected " + name)
	}
	return nil
}
func (f *fakeSystem) Inspect(context.Context, *State) (Snapshot, error) {
	f.inspectCount++
	if err := f.step("inspect"); err != nil {
		return Snapshot{}, err
	}
	if f.inspectCount > 1 && f.late.Processes != nil {
		return f.late, nil
	}
	return f.snapshot, nil
}
func (f *fakeSystem) Preflight(context.Context, *State) error { return f.step("preflight") }
func (f *fakeSystem) Enable(context.Context) (string, error) {
	if err := f.step("enable"); err != nil {
		return "", err
	}
	f.token = true
	return "12345", nil
}
func (f *fakeSystem) Load(context.Context, State) (string, error) {
	if err := f.step("load"); err != nil {
		return "", err
	}
	f.barrier = true
	return Digest("expected"), nil
}
func (f *fakeSystem) Verify(context.Context, State) error {
	if err := f.step("verify"); err != nil {
		return err
	}
	if !f.barrier || !f.token {
		return errors.New("barrier or token absent")
	}
	return nil
}
func (f *fakeSystem) ReleaseBarrier(context.Context, State) (bool, error) {
	return f.barrier, f.step("release-view")
}
func (f *fakeSystem) LaunchProxy(context.Context, *State) (Identity, error) {
	if err := f.step("proxy"); err != nil {
		return Identity{}, err
	}
	return proxyIdentity(), nil
}
func (f *fakeSystem) LaunchApp(_ context.Context, s *State) (Identity, error) {
	if err := f.step("app"); err != nil {
		return Identity{}, err
	}
	launcher := Identity{PID: 40, Started: 101, Path: Binary, UID: 0, GID: 0, RealGID: 0, SavedGID: 0}
	s.Launcher = &launcher
	return appIdentity(), nil
}
func (f *fakeSystem) StopProxy(context.Context, Identity) error { return f.step("stop-proxy") }
func (f *fakeSystem) Clear(context.Context, State) error {
	if err := f.step("clear"); err != nil {
		return err
	}
	f.barrier = false
	return nil
}
func (f *fakeSystem) DisableReference(context.Context, string) error {
	if err := f.step("disable-reference"); err != nil {
		return err
	}
	f.token = false
	return nil
}
func (f *fakeSystem) Save(s State) error {
	if err := f.step("save-" + s.Phase); err != nil {
		return err
	}
	f.saved = s
	return nil
}
func (f *fakeSystem) Remove() error {
	if err := f.step("remove"); err != nil {
		return err
	}
	f.removed = true
	return nil
}
func proxyIdentity() Identity {
	return Identity{PID: 20, Started: 100, Path: Binary, UID: 4294967294, GID: 4294967294, RealGID: 4294967294, SavedGID: 4294967294}
}
func appIdentity() Identity {
	return Identity{PID: 30, Started: 101, Path: App, UID: 501, GID: 62000, RealGID: 62000, SavedGID: 62000}
}
func freshState() State {
	return State{Version: 1, UID: 501, GID: 62000, Phase: "reserved", Wired: "en5"}
}
func activeState() State {
	s := freshState()
	s.Phase = "active"
	s.Token = "12345"
	s.RuleHash = Digest("expected")
	proxy, app := proxyIdentity(), appIdentity()
	s.Proxy, s.App = &proxy, &app
	s.SocketObservationStarted = true
	return s
}

func testSocket() Socket {
	return Socket{Holder: appIdentity(), Key: SocketKey{Handle: 9, PCB: 10, Generation: 11, Family: unix.AF_INET, Protocol: unix.IPPROTO_TCP}}
}

func TestStartEveryFailureKeepsBarrierAndNeverCleansAnApplication(t *testing.T) {
	steps := []string{"inspect", "preflight", "save-reserved", "enable", "save-enabled", "load", "save-barrier", "verify", "proxy", "save-proxy", "save-launching", "app", "save-active"}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			f := &fakeSystem{fail: step}
			s := freshState()
			err := (Controller{System: f}).Start(context.Background(), &s)
			if err == nil {
				t.Fatal("failure accepted")
			}
			if slices.Contains(f.events, "clear") || slices.Contains(f.events, "disable-reference") {
				t.Fatal("startup failure removed protection", f.events)
			}
			if slices.Contains(f.events, "app") && !slices.Contains(f.events, "verify") {
				t.Fatal("application started before a verified barrier")
			}
			if f.barrier && !f.token {
				t.Fatal("barrier lost its enable reference")
			}
		})
	}
}

func TestStartRejectsOldApplicationsAndGIDCollisions(t *testing.T) {
	for _, p := range []Identity{{Path: App, GID: 20}, {Path: "/other", UID: 500, GID: 62000}, {Path: "/other", UID: 501, RealGID: 62000}, {Path: "/other", SavedGID: 62000}} {
		f := &fakeSystem{snapshot: Snapshot{Processes: []Identity{p}}}
		s := freshState()
		if err := (Controller{System: f}).Start(context.Background(), &s); err == nil {
			t.Fatal("old application or GID collision accepted")
		}
		if len(f.events) != 1 {
			t.Fatal("changed PF before collision check", f.events)
		}
	}
	f := &fakeSystem{snapshot: Snapshot{Sockets: []Socket{testSocket()}}}
	s := freshState()
	if err := (Controller{System: f}).Start(context.Background(), &s); err == nil {
		t.Fatal("inherited socket ownership accepted")
	}
}

func TestApplicationAppearingBetweenPreflightAndLaunchIsRefused(t *testing.T) {
	f := &fakeSystem{late: Snapshot{Processes: []Identity{{Path: App, GID: 20}}}}
	s := freshState()
	if err := (Controller{System: f}).Start(context.Background(), &s); err == nil {
		t.Fatal("racing old application accepted")
	}
	if slices.Contains(f.events, "app") || !f.barrier {
		t.Fatal(f.events)
	}
}

func TestControllerCrashAndProxyCrashNeverReleaseBarrier(t *testing.T) {
	f := &fakeSystem{}
	s := freshState()
	c := Controller{System: f}
	if err := c.Start(context.Background(), &s); err != nil {
		t.Fatal(err)
	}
	// No defer cleanup runs when the owner disappears. A subsequent process
	// recovers the persisted record with the proxy absent.
	s = f.saved
	f.snapshot = Snapshot{Processes: []Identity{appIdentity()}}
	if err := c.Recover(context.Background(), &s); err == nil {
		t.Fatal("missing proxy accepted")
	}
	if !f.barrier || !f.token || f.removed {
		t.Fatal("crash made session fail open")
	}
}

func TestReleaseRefusesHelpersUnknownIdentitiesAndPassedSocketHandles(t *testing.T) {
	helper := appIdentity()
	helper.PID = 31
	helper.Path = AppBundle + "/Contents/Frameworks/helper"
	unknown := helper
	unknown.Path = "/unknown/broker"
	for _, snap := range []Snapshot{{Processes: []Identity{helper}}, {Processes: []Identity{unknown}}, {Sockets: []Socket{testSocket()}}, {Processes: []Identity{{Path: App, UID: 501, GID: 20}}}} {
		f := &fakeSystem{barrier: true, token: true, snapshot: snap}
		s := activeState()
		if err := (Controller{System: f}).Release(context.Background(), &s); err == nil {
			t.Fatal("occupied session released")
		}
		if !f.barrier || !f.token || f.removed {
			t.Fatal("protection removed")
		}
	}
}

func TestReleaseFailureRecoveryIsIdempotentAfterClear(t *testing.T) {
	for _, step := range []string{"save-releasing", "stop-proxy", "clear", "save-cleared", "disable-reference", "save-released", "remove"} {
		t.Run(step, func(t *testing.T) {
			f := &fakeSystem{barrier: true, token: true, fail: step, saved: activeState()}
			s := activeState()
			c := Controller{System: f}
			if err := c.Release(context.Background(), &s); err == nil {
				t.Fatal("injected release failure accepted")
			}
			if f.removed {
				t.Fatal("state removed after failed release")
			}
			recovered := f.saved
			if err := c.Release(context.Background(), &recovered); err != nil {
				t.Fatalf("release not recoverable: %v; events=%v", err, f.events)
			}
			if f.barrier || f.token || !f.removed {
				t.Fatal("release incomplete", f.events)
			}
		})
	}
}

func TestClearCrashWithNewUnknownOwnerRefusesFurtherCleanup(t *testing.T) {
	f := &fakeSystem{token: true, saved: activeState(), snapshot: Snapshot{Sockets: []Socket{testSocket()}}}
	s := activeState()
	s.Phase = "releasing"
	err := (Controller{System: f}).Release(context.Background(), &s)
	if err == nil || !strings.Contains(err.Error(), "barrier present: false") {
		t.Fatal("missing barrier was misreported", err)
	}
	if !f.token || f.removed {
		t.Fatal("unknown owner allowed cleanup")
	}
}

func TestSocketObservationCountsControlledHoldersAndRetainsTransferredObjects(t *testing.T) {
	s := activeState()
	controlled := testSocket()
	f := &fakeSystem{barrier: true, token: true}
	c := Controller{System: f}
	if err := c.Observe(&s, Snapshot{Sockets: []Socket{controlled, controlled}}); err != nil {
		t.Fatal(err)
	}
	if len(s.SeenSockets) != 1 || len(f.events) != 1 {
		t.Fatal("observed object not deduplicated or persisted", s.SeenSockets, f.events)
	}
	if err := c.Observe(&s, Snapshot{Sockets: []Socket{controlled}}); err != nil || len(f.events) != 1 {
		t.Fatal("unchanged history rewritten", err, f.events)
	}
	counts, err := CountSockets(s, Snapshot{Sockets: []Socket{controlled, controlled}})
	if err != nil || counts.Controlled != 1 || counts.Observed != 1 || counts.Remaining != 1 {
		t.Fatal(counts, err)
	}
	transferred := controlled
	transferred.Holder = Identity{PID: 999, Started: 500, UID: 500, GID: 20, RealGID: 20, SavedGID: 20}
	f.snapshot = Snapshot{Sockets: []Socket{transferred}}
	if err := c.Release(context.Background(), &s); err == nil || !f.barrier || !f.token || f.removed {
		t.Fatal("observed descriptor transferred to another UID was released", err, f.events)
	}
	counts, err = CountSockets(s, f.snapshot)
	if err != nil || counts.Controlled != 0 || counts.Observed != 1 || counts.Remaining != 1 {
		t.Fatal(counts, err)
	}
	transferred.Key.Generation++
	f.snapshot = Snapshot{Sockets: []Socket{transferred}}
	if err := c.Release(context.Background(), &s); err != nil || !f.removed {
		t.Fatal("reused opaque address with a new generation was treated as the original object", err)
	}
}

func TestSocketHistorySaveFailureAndUnknownKeysHoldTheBarrier(t *testing.T) {
	for _, failure := range []string{"save", "zero-handle", "zero-generation"} {
		t.Run(failure, func(t *testing.T) {
			s := activeState()
			socket := testSocket()
			f := &fakeSystem{barrier: true, token: true}
			switch failure {
			case "save":
				f.fail = "save-active"
			case "zero-handle":
				socket.Key.Handle = 0
			case "zero-generation":
				socket.Key.Generation = 0
			}
			f.snapshot = Snapshot{Processes: []Identity{appIdentity(), proxyIdentity()}, Sockets: []Socket{socket}}
			if err := (Controller{System: f}).Recover(context.Background(), &s); err == nil || s.Phase != "held" || !f.barrier || !f.token || f.removed {
				t.Fatal("unrecorded or unknown observation lost the barrier", err, f.events)
			}
		})
	}
}

func TestLegacyStateHasNoInventedSocketObservationHistory(t *testing.T) {
	s := activeState()
	s.SocketObservationStarted = false
	f := &fakeSystem{barrier: true, token: true}
	if err := (Controller{System: f}).Release(context.Background(), &s); err == nil || s.SocketObservationStarted || !f.barrier {
		t.Fatal("legacy state was treated as observed", err)
	}
	s = activeState()
	s.SeenSockets = []SocketKey{testSocket().Key, testSocket().Key}
	if err := s.Validate(); err == nil {
		t.Fatal("duplicate observed socket keys accepted")
	}
	s.SeenSockets = make([]SocketKey, 4097)
	if err := s.Validate(); err == nil {
		t.Fatal("unbounded observation history accepted")
	}
}

func TestCompleteObservationPrunesClosedObjectsWithoutGrowingSessionHistory(t *testing.T) {
	s := activeState()
	for i := range 4096 {
		key := testSocket().Key
		key.Handle = uint64(i) + 1
		s.SeenSockets = append(s.SeenSockets, key)
	}
	socket := testSocket()
	socket.Key.Handle = 5000
	f := &fakeSystem{}
	c := Controller{System: f}
	if err := c.Observe(&s, Snapshot{Sockets: []Socket{socket}}); err != nil || len(s.SeenSockets) != 1 || s.SeenSockets[0] != socket.Key {
		t.Fatal("closed short connections exhausted the active set", len(s.SeenSockets), err)
	}
	if err := c.Observe(&s, Snapshot{Sockets: []Socket{socket}}); err != nil || len(f.events) != 1 {
		t.Fatal("unchanged active set was rewritten", f.events, err)
	}
	broken := socket
	broken.Key.Generation = 0
	if _, err := CountSockets(s, Snapshot{Sockets: []Socket{broken}}); err == nil {
		t.Fatal("read-only counts reported an incomplete observed object as absent")
	}
	if err := c.Observe(&s, Snapshot{Sockets: []Socket{broken}}); err == nil || len(s.SeenSockets) != 1 {
		t.Fatal("an incomplete key silently pruned an observed object", err)
	}
}

func TestReleaseRejectsUnrecognizedKernelView(t *testing.T) {
	f := &fakeSystem{barrier: false, token: true, fail: "release-view"}
	s := activeState()
	s.Phase = "cleared"
	if err := (Controller{System: f}).Recover(context.Background(), &s); err == nil {
		t.Fatal("ambiguous release view accepted")
	}
	if !f.token || f.removed {
		t.Fatal("removed unknown PF ownership")
	}
}

func TestPIDReuseDoesNotMatchProxy(t *testing.T) {
	a := proxyIdentity()
	b := a
	b.Started++
	if SameProcess(a, b) {
		t.Fatal("reused PID accepted")
	}
	for _, mutate := range []func(*Identity){func(p *Identity) { p.UID = 501 }, func(p *Identity) { p.GID = 20 }, func(p *Identity) { p.Path = "/elsewhere" }} {
		b = a
		mutate(&b)
		if SameProcess(a, b) {
			t.Fatal(fmt.Sprint(b))
		}
	}
}

func TestReleaseWaitsForThePrivilegedGUIProducer(t *testing.T) {
	s := activeState()
	producer := Identity{PID: 40, Started: 101, Path: Binary, UID: 0}
	s.Launcher = &producer
	f := &fakeSystem{barrier: true, token: true, snapshot: Snapshot{Processes: []Identity{producer}}}
	if err := (Controller{System: f}).Release(context.Background(), &s); err == nil {
		t.Fatal("released while root GUI producer can still create the app")
	}
	if !f.barrier || !f.token {
		t.Fatal("producer escaped the barrier")
	}
	s = activeState()
	s.LaunchPending = true
	f = &fakeSystem{barrier: true, token: true}
	if err := (Controller{System: f}).Release(context.Background(), &s); err == nil {
		t.Fatal("unacknowledged launch intent released")
	}
}
