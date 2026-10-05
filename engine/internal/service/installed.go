package service

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"network-owned-engine/internal/dnsservice"
	"network-owned-engine/internal/routing"
	"network-owned-engine/internal/runtimecheck"
)

func trustedFile(path string, mode os.FileMode, uid uint32) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		return fmt.Errorf("unexpected installed file or permissions: %s", path)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Uid != uid || stat.Nlink != 1 || uid == 0 && stat.Gid != 0 {
		return fmt.Errorf("unexpected installed file ownership: %s", path)
	}
	root, err := runtimecheck.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	return root.Close()
}

// CheckInstallation verifies the existing trust boundary before any worker
// starts. It does not import binaries, rewrite DNS settings or repair permissions.
func CheckInstallation(c Config) error {
	for _, path := range []string{c.EngineConfig, c.Routes.DNSConfig, c.Routes.ChinaList, c.Routes.ExtraList, c.Routes.DomainList} {
		if err := trustedFile(path, 0o644, 0); err != nil {
			return err
		}
	}
	mode := os.FileMode(0o555)
	if c.Version == 2 {
		mode = 0o755
	}
	if err := trustedFile(c.Routes.DNSBinary, mode, 0); err != nil {
		return err
	}
	if c.Version == 2 {
		if !dnsservice.SocketActivationAvailable() {
			return errors.New("native DNS requires a CGO-enabled macOS build")
		}
		policy, err := dnsservice.Load(c.Routes.DNSConfig)
		if err != nil {
			return err
		}
		want := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr(c.Routes.DNS)}
		if policy.Port != 53 || !slices.Equal(policy.Listen, want) {
			return errors.New("native DNS listeners differ from the installed service")
		}
	}
	lines, err := routing.ReadLines(c.Routes.DNSConfig)
	if err != nil {
		return err
	}
	listener := false
	for _, line := range lines {
		if addresses, ok := strings.CutPrefix(line, "listen-address="); ok && slices.Contains(strings.Split(addresses, ","), c.Routes.DNS) {
			listener = true
		}
	}
	if !listener || c.Routes.DNS != c.Routes.WiredIP || !slices.Contains(lines, "log-queries=extra") || !slices.Contains(lines, "log-facility=/var/log/dnsmasq-network-split-query.log") {
		return errors.New("installed DNS listener or observation settings differ from the service configuration")
	}
	return nil
}
