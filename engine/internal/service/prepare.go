package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"network-owned-engine/internal/routing"
	"network-owned-engine/internal/runtimecheck"
)

// Prepare reads the current interfaces and existing user task. It writes no
// system configuration and refuses to guess a missing gateway or status path.
func Prepare(account *user.User, run func(...string) (string, error)) (Config, error) {
	c := Config{Version: 1, EngineConfig: runtimecheck.Production.Config, Routes: ProductionRoutes()}
	var proxy struct {
		Domestic, Foreign struct {
			Interface string `json:"interface"`
		}
	}
	data, err := os.ReadFile(c.EngineConfig)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &proxy); err != nil {
		return c, err
	}
	c.Routes.WiredInterface, c.Routes.WiFiInterface = proxy.Domestic.Interface, proxy.Foreign.Interface
	c.Routes.WiredService, c.Routes.WiFiService = "Ethernet", "Wi-Fi"
	if c.Routes.WiredInterface == "" || c.Routes.WiFiInterface == "" {
		return c, errors.New("installed proxy interfaces are missing")
	}
	for _, target := range []struct {
		iface   string
		gateway *string
	}{{c.Routes.WiredInterface, &c.Routes.WiredGateway}, {c.Routes.WiFiInterface, &c.Routes.WiFiGateway}} {
		out, err := run("/sbin/route", "-n", "get", "-ifscope", target.iface, "default")
		if err != nil {
			return c, err
		}
		route := routing.ParseRoute(out)
		if route.Interface != target.iface {
			return c, errors.New("scoped gateway does not match its interface")
		}
		*target.gateway = route.Gateway
	}
	out, err := run("/usr/sbin/ipconfig", "getifaddr", c.Routes.WiredInterface)
	if err != nil {
		return c, err
	}
	c.Routes.WiredIP = strings.TrimSpace(out)
	for _, name := range []string{c.Routes.WiredService, c.Routes.WiFiService} {
		out, err := run("/usr/sbin/networksetup", "-getdnsservers", name)
		if err != nil {
			return c, err
		}
		fields := strings.Fields(out)
		if len(fields) != 1 {
			return c, errors.New("expected one installed split DNS server")
		}
		address, err := netip.ParseAddr(fields[0])
		if err != nil || !address.Is4() {
			return c, errors.New("invalid system DNS address")
		}
		if c.Routes.DNS != "" && c.Routes.DNS != address.String() {
			return c, errors.New("system DNS differs between interfaces")
		}
		c.Routes.DNS = address.String()
	}
	c.Status.User, c.Status.Home = account.Username, account.HomeDir
	c.Status.State = filepath.Join(account.HomeDir, "Library/Caches/network-split-log-guard.state")
	c.Status.Log = filepath.Join(account.HomeDir, "Library/Logs/network-split-log-guard.log")
	definition := filepath.Join(account.HomeDir, "Library/LaunchAgents/com.local.network-split-log-guard.plist")
	out, err = run("/usr/bin/plutil", "-convert", "json", "-o", "-", definition)
	if err != nil {
		return c, err
	}
	var task struct {
		Label            string
		StartInterval    int
		ProgramArguments []string
	}
	if err := json.Unmarshal([]byte(out), &task); err != nil {
		return c, err
	}
	if task.Label != "com.local.network-split-log-guard" || task.StartInterval != 300 {
		return c, errors.New("unexpected installed status task")
	}
	for i, arg := range task.ProgramArguments {
		if arg == "-output" && i+1 < len(task.ProgramArguments) {
			c.Status.Output = task.ProgramArguments[i+1]
		}
	}
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c, nil
}

func WriteNew(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("could not finish %s: %w", path, err)
	}
	return nil
}
