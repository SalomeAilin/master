package wiredguard

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"
)

func Run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Println("wired-app: plan | preflight | start | status | evidence | recover | release [-uid <existing-user-id>]")
		fmt.Println("start requires the installed engine, administrator authorization, and all existing Baidu processes closed. No daemon is installed.")
		fmt.Println("evidence samples the proxy and controlled app processes three times, with private PF counters and recent proxy logs in JSON.")
		return nil
	}
	action := args[0]
	switch action {
	case "plan", "preflight", "start", "status", "evidence", "recover", "release", "_launch":
	default:
		return errors.New("unknown wired-app action")
	}
	flags := flag.NewFlagSet("wired-app "+action, flag.ContinueOnError)
	uidDefault := os.Getuid()
	if uidDefault == 0 {
		if parsed, err := strconv.Atoi(os.Getenv("SUDO_UID")); err == nil {
			uidDefault = parsed
		}
	}
	uid := flags.Uint("uid", uint(uidDefault), "existing unprivileged GUI account UID")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || uint64(*uid) > 2147483647 {
		return errors.New("invalid wired-app arguments")
	}
	if action == "plan" {
		account, err := LookupAccount(uint32(*uid))
		if err != nil {
			return err
		}
		wired, err := installedWiredInterface(ctx, false)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"application": App, "uid": account.UID, "original_gid": account.GID, "groups_before_primary_replacement": account.Groups, "proxy": "127.0.0.1:17891", "interface": wired, "anchor": Anchor, "state_directory": Directory, "deployment_verified": false, "requires": "administrator preflight, explicit app restart, live PF/socket verification and physical wired disconnect test", "boundary": "only processes and TCP/UDP sockets retaining the dedicated session credentials; external Finder/XPC brokers are not included"})
	}
	if os.Geteuid() != 0 {
		return errors.New("administrator authorization is required for PF and complete socket ownership inspection")
	}
	store := Store{Path: Directory, Owner: 0}
	if action == "evidence" {
		state, err := store.Read()
		if err != nil {
			return err
		}
		account, err := LookupAccount(state.UID)
		if err != nil {
			return err
		}
		report, err := (&Native{Store: store, Account: account}).Evidence(ctx, state)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(report)
	}
	if action == "status" {
		state, err := store.Read()
		if os.IsNotExist(err) {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"session": "absent", "verified": false})
		}
		if err != nil {
			return err
		}
		account, err := LookupAccount(state.UID)
		if err != nil {
			return err
		}
		native := &Native{Store: store, Account: account}
		snap, inspectErr := native.Inspect(ctx, &state)
		processes, sockets, ownerErr := Ownership(state, snap)
		counts, countErr := CountSockets(state, snap)
		verifyErr := native.Verify(ctx, state)
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"state": state, "controlled_processes": processes, "remaining_socket_objects": sockets, "controlled_holder_socket_objects": counts.Controlled, "seen_socket_objects_still_held": counts.Observed, "socket_observation_persisted": state.SocketObservationStarted, "status_observation_saved": false, "original_socket_credentials": "unknown: libproc does not expose so_cred", "unresolved_paths": snap.UnresolvedPaths, "barrier_verified": verifyErr == nil, "inspection_error": errorText(errors.Join(inspectErr, ownerErr, countErr, verifyErr)), "physical_disconnect_verified": false, "boundary": "ordinary-GID external brokers and socket transfers never observed by the controller are outside this session"})
	}
	if action != "preflight" {
		if err := RequireInstalled(); err != nil {
			return err
		}
	}
	if action == "_launch" {
		state, err := store.Read()
		if err != nil {
			return err
		}
		if state.UID != uint32(*uid) {
			return errors.New("launcher account differs from stored intent")
		}
		account, err := LookupAccount(state.UID)
		if err != nil {
			return err
		}
		return (&Native{Store: store, Account: account}).launchChild(ctx, state)
	}
	if action == "preflight" {
		account, err := LookupAccount(uint32(*uid))
		if err != nil {
			return err
		}
		native := &Native{Store: store, Account: account}
		_, err = store.Read()
		if err == nil {
			return errors.New("existing wired session must be inspected or released first")
		}
		if !os.IsNotExist(err) {
			return err
		}
		snap, err := native.Inspect(ctx, nil)
		if err != nil {
			return err
		}
		gid, err := SelectGID(account, snap)
		if err != nil {
			return err
		}
		for _, p := range snap.Processes {
			if IsBaidu(p) {
				return errors.New("existing Baidu process must be closed before start")
			}
		}
		if err = native.Preflight(ctx, nil); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"preflight": "passed", "uid": account.UID, "candidate_gid": gid, "unresolved_paths": snap.UnresolvedPaths, "system_changed": false, "live_disconnect_test": "not_run"})
	}
	release, err := store.Lock()
	if err != nil {
		return err
	}
	defer release()
	state, err := store.Read()
	if action == "start" {
		if err == nil {
			return errors.New("existing wired session must be recovered or released first")
		}
		if !os.IsNotExist(err) {
			return err
		}
		account, err := LookupAccount(uint32(*uid))
		if err != nil {
			return err
		}
		native := &Native{Store: store, Account: account}
		snap, err := native.Inspect(ctx, nil)
		if err != nil {
			return err
		}
		gid, err := SelectGID(account, snap)
		if err != nil {
			return err
		}
		wired, err := installedWiredInterface(ctx, true)
		if err != nil {
			return err
		}
		state = State{Version: 1, UID: account.UID, GID: gid, Phase: "reserved", Wired: wired}
		controller := Controller{System: native}
		if err = controller.Start(ctx, &state); err != nil {
			return err
		}
		if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"session": "started", "state": state, "unresolved_paths": native.lastUnresolvedPaths, "download_verified": false, "instruction": "set Baidu's HTTP proxy to 127.0.0.1:17891; verify controlled helpers and an actual download before claiming wired-only operation"}); err != nil {
			return err
		}
		for {
			if err = wait(ctx, 5*time.Second); err != nil {
				stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				if state.Proxy != nil {
					_ = native.StopProxy(stopCtx, *state.Proxy)
				}
				cancel()
				return controller.hold(&state, errors.New("controller stopped; PF retained until the controlled app and socket handles are gone"))
			}
			if err = native.Verify(ctx, state); err != nil {
				stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				if state.Proxy != nil {
					_ = native.StopProxy(stopCtx, *state.Proxy)
				}
				cancel()
				return controller.hold(&state, err)
			}
			snap, err = native.Inspect(ctx, &state)
			if err != nil {
				return controller.hold(&state, err)
			}
			if err = controller.Observe(&state, snap); err != nil {
				return controller.hold(&state, err)
			}
			processes, sockets, err := Ownership(state, snap)
			if err != nil {
				return controller.hold(&state, err)
			}
			proxyAlive := false
			for _, p := range snap.Processes {
				if state.Proxy != nil && SameProcess(p, *state.Proxy) {
					proxyAlive = true
				}
			}
			if !proxyAlive {
				return controller.hold(&state, errors.New("temporary proxy exited; PF remains installed"))
			}
			if processes == 0 && sockets == 0 {
				return controller.Release(ctx, &state)
			}
		}
	}
	if err != nil {
		return err
	}
	account, err := LookupAccount(state.UID)
	if err != nil {
		return err
	}
	controller := Controller{System: &Native{Store: store, Account: account}}
	if action == "recover" {
		return controller.Recover(ctx, &state)
	}
	return controller.Release(ctx, &state)
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// LockForUpgrade serializes the entire upgrade with session creation. A read
// followed by a separate deployment lock would leave a start/upgrade race.
func LockForUpgrade() (func(), error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("administrator authorization is required for upgrade")
	}
	store := Store{Path: Directory, Owner: 0}
	release, err := store.Lock()
	if err != nil {
		return nil, err
	}
	_, err = store.Read()
	if os.IsNotExist(err) {
		return release, nil
	}
	release()
	if err != nil {
		return nil, fmt.Errorf("cannot establish wired session state before upgrade: %w", err)
	}
	return nil, errors.New("wired-app session exists; close its controlled app and release it before upgrading")
}
