package runtimecheck

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

type State struct {
	PIDs  map[string]int
	Files map[string]string
}

func Inspect(d Paths, run func(...string) (string, error)) (State, error) {
	state := State{PIDs: map[string]int{}, Files: map[string]string{}}
	sbin := filepath.Dir(d.Tool)
	services := map[string]string{
		ProxyLabel: d.Binary,
		"system/com.local.network-split-dns-event-route-agent": filepath.Join(sbin, "network-split-dns-event-route-agent"),
		"system/homebrew.mxcl.dnsmasq":                         filepath.Join(sbin, "dnsmasq-network-split"),
	}
	for label, program := range services {
		details, err := run("/bin/launchctl", "print", label)
		if err != nil {
			return state, err
		}
		values := map[string]string{}
		for _, line := range strings.Split(details, "\n") {
			if key, value, ok := strings.Cut(strings.TrimSpace(line), " = "); ok {
				if _, exists := values[key]; !exists {
					values[key] = value
				}
			}
		}
		pid, err := strconv.Atoi(values["pid"])
		if err != nil || pid <= 0 || values["state"] != "running" || values["program"] != program {
			return state, fmt.Errorf("%s is not running the expected program", label)
		}
		state.PIDs[label] = pid
	}
	files := []string{d.Binary, d.Config, d.Plist, d.Tool,
		filepath.Join(filepath.Dir(d.Config), "dnsmasq-network-split.conf"),
		filepath.Join(filepath.Dir(d.Plist), "com.local.network-split-dns-event-route-agent.plist"),
		filepath.Join(filepath.Dir(d.Plist), HealthPlistName)}
	for _, name := range []string{"network-split-policy", "network-split-dns-event-route-agent", "dnsmasq-network-split", "china-route.sh", "network-split-guard.sh"} {
		files = append(files, filepath.Join(sbin, name))
	}
	legacy := filepath.Join(sbin, LegacyHealthScript)
	if _, err := os.Lstat(legacy); err == nil {
		files = append(files, legacy)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return state, err
	}
	health := filepath.Join(sbin, HealthBinaryName)
	if _, err := os.Lstat(health); err == nil {
		files = append(files, health)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return state, err
	}
	for _, path := range files {
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return state, err
		}
		file := os.NewFile(uintptr(fd), path)
		digest, _, err := HashFile(file)
		file.Close()
		if err != nil {
			return state, err
		}
		state.Files[path] = digest
	}
	return state, nil
}

func HashFile(file *os.File) (string, int64, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return "", 0, errors.New("unsafe or oversized maintenance file")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, (64<<20)+1))
	if err != nil || size > 64<<20 {
		return "", 0, errors.New("could not hash bounded maintenance file")
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func DirectoryNames(parent *os.Root) ([]string, error) {
	directory, err := parent.Open(".")
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	// Root.FS().ReadDir eagerly stats every entry, including protected unrelated
	// macOS databases. Select our names before inspecting any entry metadata.
	names, err := directory.Readdirnames(-1)
	slices.Sort(names)
	return names, err
}

func OpenRoot(path string) (*os.Root, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	info, err := root.Stat(".")
	if err != nil || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() || info.Mode().Perm()&0o022 != 0 {
		root.Close()
		return nil, errors.New("unsafe maintenance parent directory")
	}
	return root, nil
}
