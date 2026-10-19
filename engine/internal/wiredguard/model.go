// Package wiredguard manages an on-demand Baidu session. The PF barrier outlives
// the controller; only an explicit release after an empty ownership scan removes it.
package wiredguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	Directory = "/var/db/network-domain-wired-app"
	Binary    = "/usr/local/libexec/network-domain-engine"
	AppBundle = "/Applications/BaiduNetdisk.app"
	App       = AppBundle + "/Contents/MacOS/BaiduNetdisk"
	Anchor    = "com.apple/000.network-domain-wired-app"
	Port      = 17891
)

type Identity struct {
	PID      int    `json:"pid"`
	Started  int64  `json:"started_microseconds"`
	Path     string `json:"path"`
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`
	RealGID  uint32 `json:"real_gid"`
	SavedGID uint32 `json:"saved_gid"`
}

type SocketKey struct {
	Handle     uint64 `json:"handle"`
	PCB        uint64 `json:"pcb"`
	Generation uint64 `json:"generation"`
	Family     int    `json:"family"`
	Protocol   int    `json:"protocol"`
}

func (key SocketKey) valid() bool {
	return key.Handle != 0 && key.PCB != 0 && key.Generation != 0 &&
		(key.Family == unix.AF_INET || key.Family == unix.AF_INET6) && key.Protocol >= 0 && key.Protocol <= 255
}

// libproc exposes the holder and an opaque socket key, but not so_cred.
type Socket struct {
	Key    SocketKey
	Holder Identity
}
type Snapshot struct {
	Processes []Identity
	Sockets   []Socket
}
type Account struct {
	UID, GID   uint32
	Groups     []uint32
	Name, Home string
}

type State struct {
	Version                  int         `json:"version"`
	UID                      uint32      `json:"uid"`
	GID                      uint32      `json:"gid"`
	Phase                    string      `json:"phase"`
	Token                    string      `json:"pf_enable_token,omitempty"`
	RuleHash                 string      `json:"loaded_rule_sha256,omitempty"`
	Proxy                    *Identity   `json:"proxy,omitempty"`
	App                      *Identity   `json:"app,omitempty"`
	LastError                string      `json:"last_error,omitempty"`
	Cache                    string      `json:"proxy_cache,omitempty"`
	Wired                    string      `json:"wired_interface"`
	Launcher                 *Identity   `json:"gui_launcher,omitempty"`
	LaunchPending            bool        `json:"launch_pending,omitempty"`
	SocketObservationStarted bool        `json:"socket_observation_started,omitempty"`
	SeenSockets              []SocketKey `json:"seen_sockets,omitempty"`
}

func (s State) Validate() error {
	if s.Version != 1 || s.UID == 0 || s.UID > 2147483647 || s.GID < 62000 || s.GID > 62127 {
		return errors.New("invalid wired session identity")
	}
	if !regexp.MustCompile(`^en[0-9]+$`).MatchString(s.Wired) {
		return errors.New("invalid physical wired interface")
	}
	switch s.Phase {
	case "reserved", "enabled", "barrier", "proxy", "launching", "active", "held", "releasing", "cleared", "released":
	default:
		return errors.New("invalid wired session phase")
	}
	if s.Token != "" {
		if _, err := strconv.ParseUint(s.Token, 10, 64); err != nil {
			return errors.New("invalid PF token")
		}
	}
	if s.RuleHash != "" {
		b, err := hex.DecodeString(s.RuleHash)
		if err != nil || len(b) != 32 {
			return errors.New("invalid PF rule digest")
		}
	}
	if s.Cache != "" && (!strings.HasPrefix(s.Cache, "/private/tmp/network-domain-wired-app.") || strings.Contains(strings.TrimPrefix(s.Cache, "/private/tmp/"), "/") || strings.Contains(s.Cache, "..")) {
		return errors.New("invalid private proxy cache path")
	}
	for _, p := range []*Identity{s.Proxy, s.App} {
		if p != nil && (p.PID <= 0 || p.Started <= 0 || p.UID == 0 || !strings.HasPrefix(p.Path, "/")) {
			return errors.New("invalid recorded process identity")
		}
	}
	if s.App != nil && (s.App.Path != App || s.App.UID != s.UID || s.App.GID != s.GID || s.App.RealGID != s.GID || s.App.SavedGID != s.GID) {
		return errors.New("recorded application identity differs from the dedicated session")
	}
	if s.Proxy != nil && (s.Proxy.Path != Binary || s.Proxy.UID != 4294967294 || s.Proxy.GID != 4294967294 || s.Proxy.RealGID != 4294967294 || s.Proxy.SavedGID != 4294967294) {
		return errors.New("recorded proxy is not the dedicated nobody worker")
	}
	if s.Launcher != nil && (s.Launcher.PID <= 0 || s.Launcher.Started <= 0 || s.Launcher.UID != 0 || s.Launcher.GID != 0 || s.Launcher.RealGID != 0 || s.Launcher.SavedGID != 0 || s.Launcher.Path != Binary) {
		return errors.New("invalid privileged GUI producer identity")
	}
	if len(s.SeenSockets) > 4096 || (len(s.SeenSockets) != 0 && !s.SocketObservationStarted) {
		return errors.New("invalid socket observation history")
	}
	seen := make(map[SocketKey]bool, len(s.SeenSockets))
	for _, key := range s.SeenSockets {
		if !key.valid() || seen[key] {
			return errors.New("invalid or duplicate observed socket key")
		}
		seen[key] = true
	}
	return nil
}

func Digest(rules string) string { h := sha256.Sum256([]byte(rules)); return hex.EncodeToString(h[:]) }

func Rules(s State) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf(`pass out quick on lo0 inet proto tcp from 127.0.0.1 to 127.0.0.1 port = %[1]d user = %[2]d group = %[3]d flags any no state label "wired-app-loopback"
pass in quick on lo0 inet proto tcp from 127.0.0.1 to 127.0.0.1 port = %[1]d user = 0 group = 0 flags any no state label "wired-app-root-listener"
block drop in quick on lo0 inet proto tcp from 127.0.0.1 to 127.0.0.1 port = %[1]d label "wired-app-deny-server"
pass out quick on lo0 inet proto tcp from 127.0.0.1 port = %[1]d to 127.0.0.1 user = 0 group = 0 flags any no state label "wired-app-server-reply"
pass in quick on lo0 inet proto tcp from 127.0.0.1 port = %[1]d to 127.0.0.1 user = %[2]d group = %[3]d flags any no state label "wired-app-client-reply"
pass out quick on %[4]s inet proto tcp all user = %[2]d group = %[3]d flags any no state label "wired-app-wired-tcp-out"
pass in quick on %[4]s inet proto tcp all user = %[2]d group = %[3]d flags any no state label "wired-app-wired-tcp-in"
block drop out quick proto tcp all user = %[2]d group = %[3]d label "wired-app-deny-tcp"
block drop out quick proto udp all user = %[2]d group = %[3]d label "wired-app-deny-udp"
block drop in quick proto tcp all user = %[2]d group = %[3]d label "wired-app-deny-tcp-in"
block drop in quick proto udp all user = %[2]d group = %[3]d label "wired-app-deny-udp-in"
`, Port, s.UID, s.GID, s.Wired), nil
}

func SameProcess(a, b Identity) bool {
	return a.PID == b.PID && a.Started == b.Started && a.Path == b.Path && a.UID == b.UID && a.GID == b.GID && a.RealGID == b.RealGID && a.SavedGID == b.SavedGID
}

func IsBaidu(p Identity) bool {
	if strings.HasPrefix(p.Path, AppBundle+"/") {
		return true
	}
	base := p.Path[strings.LastIndex(p.Path, "/")+1:]
	switch strings.ToLower(base) {
	case "baidunetdisk", "baidunetdiskhost", "netdisk_service", "baidunetdiskhelper":
		return true
	}
	return false
}

func sessionHolder(s State, holder Identity) bool {
	return holder.GID == s.GID || holder.RealGID == s.GID || holder.SavedGID == s.GID
}

type SocketCounts struct {
	Controlled int
	Observed   int
	Remaining  int
}

func CountSockets(s State, snap Snapshot) (SocketCounts, error) {
	var counts SocketCounts
	seen := make(map[SocketKey]bool, len(s.SeenSockets))
	handles := make(map[uint64]bool, len(s.SeenSockets))
	for _, key := range s.SeenSockets {
		seen[key] = true
		handles[key.Handle] = true
	}
	controlled, observed, remaining := map[SocketKey]bool{}, map[SocketKey]bool{}, map[SocketKey]bool{}
	for _, socket := range snap.Sockets {
		if handles[socket.Key.Handle] && !socket.Key.valid() {
			return counts, errors.New("previously observed socket has an incomplete key")
		}
		if sessionHolder(s, socket.Holder) {
			if socket.Holder.PID <= 0 || socket.Holder.Started <= 0 || !socket.Key.valid() {
				return counts, errors.New("controlled socket has an incomplete holder identity or opaque key")
			}
			controlled[socket.Key], remaining[socket.Key] = true, true
		}
		if seen[socket.Key] {
			observed[socket.Key], remaining[socket.Key] = true, true
		}
	}
	counts.Controlled, counts.Observed, counts.Remaining = len(controlled), len(observed), len(remaining)
	return counts, nil
}

func Ownership(s State, snap Snapshot) (processes int, sockets int, err error) {
	for _, p := range snap.Processes {
		if s.Launcher != nil && p.PID == s.Launcher.PID {
			processes++
			if !SameProcess(p, *s.Launcher) {
				err = errors.New("GUI producer identity changed; release refused")
			}
		}
		if p.GID == s.GID || p.RealGID == s.GID || p.SavedGID == s.GID {
			processes++
			if p.UID != s.UID || p.GID != s.GID || p.RealGID != s.GID || p.SavedGID != s.GID || !strings.HasPrefix(p.Path, AppBundle+"/") {
				err = errors.New("unrecognized process uses the reserved GID; barrier retained")
			}
		}
		if IsBaidu(p) && (p.UID != s.UID || p.GID != s.GID) {
			err = errors.New("Baidu process outside the controlled session; coverage is incomplete")
		}
	}
	counts, socketErr := CountSockets(s, snap)
	sockets = counts.Remaining
	err = errors.Join(err, socketErr)
	if s.LaunchPending && s.Launcher == nil {
		err = errors.New("unacknowledged GUI launch intent; manual process inspection is required")
	}
	return
}

// System keeps privileged effects injectable. Tests never load live PF rules or
// launch the user's application.
type System interface {
	Inspect(context.Context, *State) (Snapshot, error)
	Preflight(context.Context, *State) error
	Enable(context.Context) (string, error)
	Load(context.Context, State) (string, error)
	Verify(context.Context, State) error
	ReleaseBarrier(context.Context, State) (bool, error)
	LaunchProxy(context.Context, *State) (Identity, error)
	LaunchApp(context.Context, *State) (Identity, error)
	StopProxy(context.Context, Identity) error
	Clear(context.Context, State) error
	DisableReference(context.Context, string) error
	Save(State) error
	Remove() error
}

type Controller struct{ System System }

// Observe records keys while their holder still has the session identity. It
// cannot discover a transfer that completed before any such observation.
func (c Controller) Observe(s *State, snap Snapshot) error {
	seen := make(map[SocketKey]bool, len(s.SeenSockets))
	handles := make(map[uint64]bool, len(s.SeenSockets))
	for _, key := range s.SeenSockets {
		seen[key] = true
		handles[key.Handle] = true
	}
	present := make(map[SocketKey]bool, len(snap.Sockets))
	for _, socket := range snap.Sockets {
		if socket.Key.valid() {
			present[socket.Key] = true
		} else if handles[socket.Key.Handle] {
			return errors.New("previously observed socket has an incomplete key; barrier retained")
		}
	}
	changed := !s.SocketObservationStarted
	var keys []SocketKey
	for _, key := range s.SeenSockets {
		if present[key] {
			keys = append(keys, key)
		} else {
			delete(seen, key)
			changed = true
		}
	}
	for _, socket := range snap.Sockets {
		if !sessionHolder(*s, socket.Holder) {
			continue
		}
		if socket.Holder.PID <= 0 || socket.Holder.Started <= 0 || !socket.Key.valid() {
			return errors.New("cannot record a controlled socket with an incomplete holder identity or opaque key")
		}
		if !seen[socket.Key] {
			if len(keys) == 4096 {
				return errors.New("socket observation history exceeds limit; barrier retained")
			}
			keys = append(keys, socket.Key)
			seen[socket.Key], changed = true, true
		}
	}
	if changed {
		s.SocketObservationStarted = true
		s.SeenSockets = keys
		return c.System.Save(*s)
	}
	return nil
}

func (c Controller) hold(s *State, err error) error {
	if !releasing(s.Phase) {
		s.Phase = "held"
	}
	s.LastError = err.Error()
	return errors.Join(err, c.System.Save(*s))
}

func releasing(phase string) bool {
	return phase == "releasing" || phase == "cleared" || phase == "released"
}

func (c Controller) Start(ctx context.Context, s *State) error {
	if err := s.Validate(); err != nil {
		return err
	}
	snap, err := c.System.Inspect(ctx, nil)
	if err != nil {
		return err
	}
	for _, p := range snap.Processes {
		if IsBaidu(p) || p.GID == s.GID || p.RealGID == s.GID || p.SavedGID == s.GID {
			return errors.New("old Baidu process or GID collision; close the existing app before starting")
		}
	}
	for _, socket := range snap.Sockets {
		if sessionHolder(*s, socket.Holder) {
			return errors.New("reserved GID already holds a socket")
		}
	}
	if err = c.System.Preflight(ctx, nil); err != nil {
		return err
	}
	s.Phase = "reserved"
	if err = c.System.Save(*s); err != nil {
		return err
	}
	s.Token, err = c.System.Enable(ctx)
	if err != nil {
		return c.hold(s, err)
	}
	s.Phase = "enabled"
	if err = c.System.Save(*s); err != nil {
		return err
	}
	s.RuleHash, err = c.System.Load(ctx, *s)
	if err != nil {
		return c.hold(s, err)
	}
	s.Phase = "barrier"
	if err = c.System.Save(*s); err != nil {
		return err
	}
	if err = c.System.Verify(ctx, *s); err != nil {
		return c.hold(s, err)
	}
	proxy, err := c.System.LaunchProxy(ctx, s)
	if err != nil {
		return c.hold(s, err)
	}
	s.Proxy, s.Phase = &proxy, "proxy"
	if err = c.System.Save(*s); err != nil {
		return err
	}
	// Recheck immediately before launch. A foreground guard cannot prevent a
	// different launcher from creating an unrelated Baidu process later.
	snap, err = c.System.Inspect(ctx, s)
	if err != nil {
		return c.hold(s, err)
	}
	for _, p := range snap.Processes {
		if IsBaidu(p) {
			return c.hold(s, errors.New("Baidu appeared outside the launcher"))
		}
	}
	s.Phase = "launching"
	s.LaunchPending = true
	if err = c.System.Save(*s); err != nil {
		return err
	}
	app, err := c.System.LaunchApp(ctx, s)
	if err != nil {
		return c.hold(s, err)
	}
	s.App, s.Phase = &app, "active"
	s.LaunchPending = false
	if err = c.System.Save(*s); err != nil {
		return err
	}
	snap, err = c.System.Inspect(ctx, s)
	if err != nil {
		return c.hold(s, err)
	}
	if err = c.Observe(s, snap); err != nil {
		return c.hold(s, err)
	}
	_, _, err = Ownership(*s, snap)
	if err != nil {
		return c.hold(s, err)
	}
	return nil
}

func (c Controller) Recover(ctx context.Context, s *State) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if releasing(s.Phase) {
		return c.Release(ctx, s)
	}
	// Recovery never removes a barrier or starts an application automatically.
	if s.RuleHash == "" {
		return c.hold(s, errors.New("incomplete session; administrator must inspect PF before release"))
	}
	if err := c.System.Verify(ctx, *s); err != nil {
		return c.hold(s, err)
	}
	snap, err := c.System.Inspect(ctx, s)
	if err != nil {
		return c.hold(s, err)
	}
	if err = c.Observe(s, snap); err != nil {
		return c.hold(s, err)
	}
	_, _, err = Ownership(*s, snap)
	if err != nil {
		return c.hold(s, err)
	}
	if s.Proxy != nil {
		for _, p := range snap.Processes {
			if SameProcess(p, *s.Proxy) {
				return nil
			}
		}
	}
	return c.hold(s, errors.New("proxy absent; barrier retained, close the controlled app and release before a new start"))
}

func (c Controller) Release(ctx context.Context, s *State) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if s.RuleHash == "" || s.Token == "" {
		return c.hold(s, errors.New("incomplete PF ownership record; automatic release refused"))
	}
	if s.App != nil && !s.SocketObservationStarted {
		return c.hold(s, errors.New("session has no persisted socket observations; inspect and recover it explicitly before release"))
	}
	barrier := true
	if releasing(s.Phase) {
		var err error
		barrier, err = c.System.ReleaseBarrier(ctx, *s)
		if err != nil {
			return c.hold(s, err)
		}
	} else if err := c.System.Verify(ctx, *s); err != nil {
		return c.hold(s, err)
	}
	for range 2 {
		snap, err := c.System.Inspect(ctx, s)
		if err != nil {
			return c.hold(s, err)
		}
		if err = c.Observe(s, snap); err != nil {
			return c.hold(s, err)
		}
		p, sockets, err := Ownership(*s, snap)
		if err != nil || p != 0 || sockets != 0 {
			return c.hold(s, errors.Join(fmt.Errorf("controlled processes or sockets remain; release refused (barrier present: %t)", barrier), err))
		}
	}
	s.Phase = "releasing"
	if err := c.System.Save(*s); err != nil {
		return err
	}
	if s.Proxy != nil {
		if err := c.System.StopProxy(ctx, *s.Proxy); err != nil {
			return c.hold(s, err)
		}
	}
	if barrier {
		if err := c.System.Clear(ctx, *s); err != nil {
			return c.hold(s, err)
		}
	}
	s.Phase = "cleared"
	if err := c.System.Save(*s); err != nil {
		return err
	}
	if err := c.System.DisableReference(ctx, s.Token); err != nil {
		return c.hold(s, err)
	}
	s.Phase = "released"
	if err := c.System.Save(*s); err != nil {
		return err
	}
	return c.System.Remove()
}
