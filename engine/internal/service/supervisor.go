package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"network-owned-engine/internal/healthcheck"
	"network-owned-engine/internal/runtimecheck"
)

type Supervisor struct {
	Jobs []Job
	Run  func(...string) (string, error)
	Wait func(context.Context, time.Duration) error
	Log  func(string, ...any)
}

func (s *Supervisor) inspect(job Job) (bool, error) {
	out, err := s.Run("/bin/launchctl", "print", "system/"+job.Label)
	if code, known := runtimecheck.ExitCode(err); known && code == 113 {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !job.Matches(ParseLaunch(out)) {
		return false, fmt.Errorf("refusing an unrelated or stale job: %s", job.Label)
	}
	return true, nil
}

func (s *Supervisor) bootstrap(ctx context.Context, job Job) (bool, error) {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		_, err := s.Run("/bin/launchctl", "bootstrap", "system", job.Path())
		if err == nil {
			break
		}
		if code, known := runtimecheck.ExitCode(err); !known || code != 5 || attempt == 9 {
			return false, err
		}
		if err := s.Wait(ctx, 500*time.Millisecond); err != nil {
			return false, err
		}
	}
	found, err := s.inspect(job)
	if err != nil {
		return true, err
	}
	if !found {
		return true, fmt.Errorf("job not registered: %s", job.Label)
	}
	return true, nil
}

func (s *Supervisor) stop(job Job) error {
	found, err := s.inspect(job)
	if err != nil || !found {
		return err
	}
	_, err = s.Run("/bin/launchctl", "bootout", "system/"+job.Label)
	if code, known := runtimecheck.ExitCode(err); known && code == 113 {
		return nil
	}
	return err
}

// Run adopts only jobs with the expected file, executable and arguments. A
// supervisor restart leaves healthy workers alone; normal shutdown unloads them.
func (s *Supervisor) RunUntilCancelled(ctx context.Context) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	loaded := make([]bool, len(s.Jobs))
	for i, job := range s.Jobs {
		found, err := s.inspect(job)
		if err != nil {
			return err
		}
		loaded[i] = found
	}
	var created []Job
	for i, job := range s.Jobs {
		if loaded[i] {
			continue
		}
		createdNow, err := false, ctx.Err()
		if err == nil {
			createdNow, err = s.bootstrap(ctx, job)
		}
		if createdNow {
			created = append(created, job)
		}
		if err != nil {
			var failures []error
			for j := len(created) - 1; j >= 0; j-- {
				failures = append(failures, s.stop(created[j]))
			}
			return errors.Join(append([]error{err}, failures...)...)
		}
	}
	s.Log("unified service active; workers=%d", len(s.Jobs))
	defer func() {
		var failures []error
		for i := len(s.Jobs) - 1; i >= 0; i-- {
			if err := s.stop(s.Jobs[i]); err != nil {
				s.Log("worker shutdown failed label=%s error=%v", s.Jobs[i].Label, err)
				failures = append(failures, err)
			}
		}
		if len(failures) > 0 {
			resultErr = fmt.Errorf("worker shutdown incomplete: %w", errors.Join(failures...))
		}
	}()
	for {
		if err := s.Wait(ctx, 30*time.Second); err != nil {
			return err
		}
		for _, job := range s.Jobs {
			found, err := s.inspect(job)
			if err != nil {
				s.Log("worker inspection failed label=%s error=%v", job.Label, err)
				continue
			}
			if !found {
				if _, err := s.bootstrap(ctx, job); err != nil {
					s.Log("worker restore failed label=%s error=%v", job.Label, err)
				}
			}
		}
	}
}

func Run(ctx context.Context, path string) error {
	if os.Geteuid() != 0 {
		return errors.New("service requires administrator privileges")
	}
	if path != ConfigPath {
		return errors.New("service requires its installed configuration")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil || executable != Binary {
		return errors.New("service must run its installed executable")
	}
	c, err := Load(path, true)
	if err != nil {
		return err
	}
	if err := trustedFile(Binary, 0o755, 0); err != nil {
		return err
	}
	if err := CheckInstallation(c); err != nil {
		return err
	}
	release, err := healthcheck.LockState(LockPath)
	if err != nil {
		return err
	}
	defer release()
	parent, err := runtimecheck.OpenRoot(JobsDirectory)
	if err != nil {
		return err
	}
	parent.Close()
	jobs := Jobs(c)
	for _, job := range jobs {
		info, err := os.Lstat(job.Path())
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 || info.Sys().(*syscall.Stat_t).Uid != 0 {
			return fmt.Errorf("unsafe worker definition: %s", job.Label)
		}
		want, err := Plist(job.Definition)
		if err != nil {
			return err
		}
		got, err := os.ReadFile(job.Path())
		if err != nil || string(got) != string(want) {
			return fmt.Errorf("worker definition does not match configuration: %s", job.Label)
		}
	}
	log := func(format string, args ...any) {
		logger := healthcheck.Runner{LogPath: "/var/log/network-split-service.log", Now: time.Now}
		if err := logger.Logf(format, args...); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	s := Supervisor{Jobs: jobs, Run: func(args ...string) (string, error) {
		limit := 8 * time.Second
		if len(args) > 1 && args[1] == "bootout" {
			limit = 20 * time.Second
		}
		return runtimecheck.RunContext(context.Background(), limit, args...)
	}, Log: log, Wait: func(ctx context.Context, d time.Duration) error {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}}
	return s.RunUntilCancelled(ctx)
}
