package wiredguard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"

	"network-owned-engine/internal/service"
)

func installedWiredInterface(ctx context.Context, full bool) (string, error) {
	const path = "/usr/local/etc/network-domain-proxy.json"
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	st := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || st.Uid != 0 || st.Nlink != 1 || info.Size() > 4<<20 {
		return "", errors.New("unsafe installed proxy policy")
	}
	var policy struct {
		Domestic, Foreign struct {
			Interface string `json:"interface"`
		}
	}
	decoder := json.NewDecoder(io.LimitReader(f, (4<<20)+1))
	if err = decoder.Decode(&policy); err != nil {
		return "", err
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return "", errors.New("trailing installed proxy policy data")
	}
	wired := policy.Domestic.Interface
	if !regexp.MustCompile(`^en[0-9]+$`).MatchString(wired) || wired == policy.Foreign.Interface {
		return "", errors.New("installed wired interface is not distinct and physical")
	}
	if !full {
		return wired, nil
	}
	c, err := service.Load(service.ConfigPath, true)
	if err != nil {
		return "", err
	}
	if c.Routes.WiredInterface != wired {
		return "", errors.New("installed proxy and service wired interfaces differ")
	}
	ports, err := command(ctx, "", "/usr/sbin/networksetup", "-listallhardwareports")
	if err != nil {
		return "", err
	}
	if !IsEthernetHardware(ports, wired) {
		return "", errors.New("configured wired interface is not an identified Ethernet/LAN hardware port")
	}
	return wired, nil
}

func IsEthernetHardware(text, device string) bool {
	port := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if name, ok := strings.CutPrefix(line, "Hardware Port: "); ok {
			port = strings.ToLower(name)
		}
		if dev, ok := strings.CutPrefix(line, "Device: "); ok && dev == device {
			return !strings.Contains(port, "wi-fi") && !strings.Contains(port, "airport") && (strings.Contains(port, "ethernet") || strings.Contains(port, "lan"))
		}
	}
	return false
}
