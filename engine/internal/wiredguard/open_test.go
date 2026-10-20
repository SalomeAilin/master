package wiredguard

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func reusableFixture() (State, Identity, Snapshot) {
	s := freshState()
	s.Phase, s.Token, s.RuleHash = "active", "12345", Digest("rules")
	s.SocketObservationStarted = true
	app, proxy := appIdentity(), proxyIdentity()
	launcher := Identity{PID: 40, Started: 101, Path: Binary}
	s.App, s.Proxy, s.Launcher = &app, &proxy, &launcher
	controller := Identity{PID: 50, Started: 102, Path: Binary}
	return s, controller, Snapshot{Processes: []Identity{app, proxy, launcher}}
}

func TestReopenRejectsIncompleteOrUncontrolledSessions(t *testing.T) {
	s, controller, snap := reusableFixture()
	if err := reusableSession(s, s.UID, controller, snap); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*State, *Identity, *Snapshot){
		"other user":      func(s *State, _ *Identity, _ *Snapshot) { s.UID++ },
		"held":            func(s *State, _ *Identity, _ *Snapshot) { s.Phase = "held" },
		"pending launch":  func(s *State, _ *Identity, _ *Snapshot) { s.LaunchPending = true },
		"no observations": func(s *State, _ *Identity, _ *Snapshot) { s.SocketObservationStarted = false },
		"recorded error":  func(s *State, _ *Identity, _ *Snapshot) { s.LastError = "failed" },
		"no producer":     func(s *State, _ *Identity, _ *Snapshot) { s.Launcher = nil },
		"no proxy":        func(s *State, _ *Identity, _ *Snapshot) { s.Proxy = nil },
		"no app":          func(s *State, _ *Identity, _ *Snapshot) { s.App = nil },
		"controller user": func(_ *State, p *Identity, _ *Snapshot) { p.UID = 501 },
		"controller path": func(_ *State, p *Identity, _ *Snapshot) { p.Path = "/tmp/other" },
		"missing process": func(_ *State, _ *Identity, snap *Snapshot) { snap.Processes = snap.Processes[1:] },
		"reused PID": func(_ *State, _ *Identity, snap *Snapshot) {
			snap.Processes[0].Started++
		},
		"ordinary instance": func(s *State, _ *Identity, snap *Snapshot) {
			p := *s.App
			p.PID, p.GID, p.RealGID, p.SavedGID = 60, 20, 20, 20
			snap.Processes = append(snap.Processes, p)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s, controller, snap := reusableFixture()
			change(&s, &controller, &snap)
			if err := reusableSession(s, 501, controller, snap); err == nil {
				t.Fatal("unsafe existing session accepted")
			}
		})
	}
}

func TestReopenSessionComparisonAllowsOnlyObservationChanges(t *testing.T) {
	a, _, _ := reusableFixture()
	b := a
	b.SeenSockets = []SocketKey{{Handle: 1}}
	if !sameSession(a, b) {
		t.Fatal("new socket observation changed the launch identity")
	}
	b.RuleHash = Digest("different rules")
	if sameSession(a, b) {
		t.Fatal("changed barrier accepted")
	}
	b = a
	app := *a.App
	app.Started++
	b.App = &app
	if sameSession(a, b) {
		t.Fatal("reused application PID accepted")
	}
}

func TestControllerLockOwnerRequiresAnotherLiveProcess(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "state"), Owner: uint32(os.Getuid())}
	release, err := s.Lock()
	if err != nil {
		t.Fatal(err)
	}
	release()
	if _, err := s.controllerPID(); err == nil {
		t.Fatal("unlocked state accepted")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestControllerLockOwnerHelper$")
	cmd.Env = append(os.Environ(), "WIRED_TEST_LOCK="+s.Path)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		input.Close()
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	if err = output.(*os.File).SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if text, err := bufio.NewReader(output).ReadString('\n'); err != nil || text != "ready\n" {
		t.Fatalf("lock helper did not start: %q, %v", text, err)
	}
	pid, err := s.controllerPID()
	if err != nil || pid != cmd.Process.Pid {
		t.Fatalf("wrong lock owner: %d, %v", pid, err)
	}
	// Querying from this process must not release the helper's lock.
	if pid2, err := s.controllerPID(); err != nil || pid2 != pid {
		t.Fatalf("lock query changed the owner: %d, %v", pid2, err)
	}
	input.Close()
	if err = cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.controllerPID(); err == nil {
		t.Fatal("exited controller accepted")
	}
}

func TestControllerLockOwnerHelper(t *testing.T) {
	path := os.Getenv("WIRED_TEST_LOCK")
	if path == "" {
		t.Skip("test subprocess only")
	}
	release, err := (Store{Path: path, Owner: uint32(os.Getuid())}).Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	fmt.Println("ready")
	bufio.NewReader(os.Stdin).ReadByte()
}
