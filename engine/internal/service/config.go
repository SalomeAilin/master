// Package service owns the single application entry and its launchd-managed
// worker processes. DNS remains the existing, separately licensed dependency.
package service

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"network-owned-engine/internal/routing"
	"network-owned-engine/internal/runtimecheck"
)

const Label = runtimecheck.ServiceLabel
const Binary = "/usr/local/libexec/network-domain-engine"
const ConfigPath = runtimecheck.ServiceConfigPath
const JobsDirectory = runtimecheck.JobsDirectory
const PlistPath = "/Library/LaunchDaemons/" + Label + ".plist"
const LockPath = "/var/db/network-split-service.flock"
const ParentExitTimeout = 240

type StatusConfig struct {
	User   string `json:"user"`
	Home   string `json:"home"`
	Output string `json:"output"`
	State  string `json:"state"`
	Log    string `json:"log"`
}

type Config struct {
	Version      int            `json:"version"`
	EngineConfig string         `json:"engine_config"`
	Routes       routing.Config `json:"routes"`
	Status       StatusConfig   `json:"status"`
}

func ProductionRoutes() routing.Config {
	return routing.Config{ChinaList: "/usr/local/etc/china_ip_list.txt", ExtraList: "/usr/local/etc/domestic_extra_routes.txt", DomainList: "/usr/local/etc/domestic_domains.conf",
		DNSConfig: "/usr/local/etc/dnsmasq-network-split.conf", DNSBinary: "/usr/local/sbin/dnsmasq-network-split", GuardLock: "/var/db/network-split-guard.flock", ChinaLock: "/var/db/china-route.flock",
		ForceRebuild: "/var/db/china-route-force-rebuild", GuardLog: "/var/log/network-split-guard.log", ChinaLog: "/var/log/china-route.log"}
}

func (c Config) Validate() error {
	if c.Version != 1 || c.EngineConfig != "/usr/local/etc/network-domain-proxy.json" {
		return errors.New("unexpected unified configuration")
	}
	if err := c.Routes.Validate(); err != nil {
		return err
	}
	fixed := ProductionRoutes()
	for _, pair := range [][2]string{{c.Routes.ChinaList, fixed.ChinaList}, {c.Routes.ExtraList, fixed.ExtraList}, {c.Routes.DomainList, fixed.DomainList}, {c.Routes.DNSConfig, fixed.DNSConfig}, {c.Routes.DNSBinary, fixed.DNSBinary},
		{c.Routes.GuardLock, fixed.GuardLock}, {c.Routes.ChinaLock, fixed.ChinaLock}, {c.Routes.ForceRebuild, fixed.ForceRebuild}, {c.Routes.GuardLog, fixed.GuardLog}, {c.Routes.ChinaLog, fixed.ChinaLog}} {
		if pair[0] != pair[1] {
			return errors.New("unexpected managed routing path")
		}
	}
	account, err := user.Lookup(c.Status.User)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid <= 0 || c.Status.Home != account.HomeDir || !filepath.IsAbs(c.Status.Home) {
		return errors.New("status worker must use a real unprivileged account")
	}
	for _, path := range []string{c.Status.Output, c.Status.State, c.Status.Log} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || !strings.HasPrefix(path, c.Status.Home+string(os.PathSeparator)) {
			return errors.New("status paths must stay within its user's home")
		}
	}
	if c.Status.Output == c.Status.State || c.Status.Output == c.Status.Log || c.Status.State == c.Status.Log {
		return errors.New("status paths must differ")
	}
	return nil
}

func Load(path string, installed bool) (Config, error) {
	c := Config{Routes: ProductionRoutes()}
	if installed {
		parent, err := runtimecheck.OpenRoot(filepath.Dir(path))
		if err != nil {
			return c, err
		}
		parent.Close()
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return c, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 || info.Mode().Perm()&0o022 != 0 {
		return c, errors.New("unsafe unified configuration file")
	}
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Nlink != 1 || installed && (stat.Uid != 0 || info.Mode().Perm() != 0o600) {
		return c, errors.New("unified configuration must be private and root-owned")
	}
	decoder := json.NewDecoder(io.LimitReader(f, (64<<10)+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return c, errors.New("trailing unified configuration data")
	}
	return c, c.Validate()
}
