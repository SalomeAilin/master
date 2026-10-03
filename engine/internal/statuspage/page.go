package statuspage

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"network-owned-engine/internal/healthcheck"
)

//go:embed page.html
var pageHTML string

var page = template.Must(template.New("status").Parse(pageHTML))

func (r Report) HTML() ([]byte, error) {
	var b bytes.Buffer
	if err := page.Execute(&b, r); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writableFile(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return errors.New("unsafe status output")
	}
	return nil
}

func atomicWrite(path string, data []byte) error {
	if err := writableFile(path); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp.")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

const logLimit = 1 << 20

// appendLog bounds the program's own history to one file and three archives.
// Unknown paths and oversized preexisting archives are preserved for review.
func appendLog(path, line string) error {
	if len(line) > 8192 {
		return errors.New("status log entry too large")
	}
	for i := 0; i <= 3; i++ {
		name := path
		if i > 0 {
			name = fmt.Sprintf("%s.%d", path, i)
		}
		if err := writableFile(name); err != nil {
			return err
		}
		if info, err := os.Stat(name); err == nil && info.Size() > logLimit {
			return errors.New("preexisting status log exceeds limit; review before migration")
		}
	}
	if info, err := os.Stat(path); err == nil && info.Size()+int64(len(line)) > logLimit {
		if err := os.Remove(path + ".3"); err != nil && !os.IsNotExist(err) {
			return err
		}
		for i := 2; i >= 0; i-- {
			from := path
			if i > 0 {
				from = fmt.Sprintf("%s.%d", path, i)
			}
			to := fmt.Sprintf("%s.%d", path, i+1)
			if err := os.Rename(from, to); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_WRONLY|syscall.O_APPEND|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}

// Publish serializes manual and launchd writers and atomically replaces the
// existing page. The summary excludes volatile timings, avoiding a log per tick.
func (r Report) Publish(htmlPath, statePath, logPath string) error {
	for _, path := range []string{htmlPath, statePath, logPath} {
		if !filepath.IsAbs(path) {
			return errors.New("status outputs require absolute paths")
		}
	}
	if htmlPath == statePath || htmlPath == logPath || statePath == logPath {
		return errors.New("status output paths must differ")
	}
	release, err := healthcheck.LockState(statePath + ".lock")
	if err != nil {
		return err
	}
	defer release()
	html, err := r.HTML()
	if err != nil {
		return err
	}
	if err := atomicWrite(htmlPath, html); err != nil {
		return err
	}
	summary := struct {
		State           string
		Checks, Domains []Row
	}{State: r.State, Checks: append([]Row(nil), r.Checks...), Domains: r.Domains}
	for i := range summary.Checks {
		if strings.HasPrefix(summary.Checks[i].Name, "https://") {
			summary.Checks[i].Detail, _, _ = strings.Cut(summary.Checks[i].Detail, ";")
		}
	}
	data, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	previous, err := boundedRead(statePath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if bytes.Equal(previous, data) {
		return nil
	}
	line := fmt.Sprintf("%s state=%s checks=%d domains=%d\n", r.Updated.Format("2006-01-02 15:04:05"), r.State, len(r.Checks), len(r.Domains))
	if err := appendLog(logPath, line); err != nil {
		return err
	}
	return atomicWrite(statePath, data)
}
