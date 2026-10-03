package healthcheck

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

var ErrInvalidState = errors.New("invalid or stale health state")

type State struct {
	Failures, Interval, LastProbe, Cooldown, Baseline, Slow int64
	Samples                                                 []int64
}

func Initial() State { return State{Interval: 30} }

func Decode(data []byte, now int64) (State, error) {
	invalid := ErrInvalidState
	if len(data) > 4096 {
		return State{}, invalid
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if _, exists := values[key]; !ok || exists {
			return State{}, invalid
		}
		values[key] = value
	}
	if len(values) != 8 || values["version"] != "1" {
		return State{}, invalid
	}
	s := State{}
	for key, target := range map[string]*int64{"failure_count": &s.Failures, "probe_interval": &s.Interval,
		"last_probe": &s.LastProbe, "cooldown_until": &s.Cooldown, "baseline_ms": &s.Baseline, "slow_count": &s.Slow} {
		value, ok := values[key]
		if !ok || len(value) == 0 || len(value) > 10 || strings.Trim(value, "0123456789") != "" {
			return State{}, invalid
		}
		*target, _ = strconv.ParseInt(value, 10, 64)
	}
	samples, ok := values["probe_samples"]
	if !ok || len(samples) > 35 {
		return State{}, invalid
	}
	if samples != "" {
		for _, value := range strings.Split(samples, ",") {
			if len(value) == 0 || len(value) > 5 || strings.Trim(value, "0123456789") != "" {
				return State{}, invalid
			}
			number, _ := strconv.ParseInt(value, 10, 64)
			if number > 10000 {
				return State{}, invalid
			}
			s.Samples = append(s.Samples, number)
		}
	}
	if len(s.Samples) > 6 || s.Failures > 1000000 || s.Baseline > 10000 || s.Slow >= 3 ||
		s.LastProbe > now || now-s.LastProbe > 600 || s.Cooldown > now+600 ||
		(s.Interval != 30 && s.Interval != 60 && s.Interval != 120) || (s.Interval != 30 && s.Cooldown > now) {
		return State{}, invalid
	}
	return s, nil
}

// Read loads a bounded regular state file. Invalid formats can reset the
// scheduler; filesystem access and identity failures must remain visible.
func Read(path string, now int64) (State, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return State{}, err
	}
	if !info.Mode().IsRegular() || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return State{}, errors.New("unsafe health state")
	}
	if info.Size() > 4096 {
		return State{}, ErrInvalidState
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return State{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return State{}, errors.New("health state changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return State{}, err
	}
	return Decode(data, now)
}

func (s State) Encode() []byte {
	var samples []string
	for _, sample := range s.Samples {
		samples = append(samples, strconv.FormatInt(sample, 10))
	}
	return []byte(fmt.Sprintf("version=1\nfailure_count=%d\nprobe_interval=%d\nlast_probe=%d\ncooldown_until=%d\nbaseline_ms=%d\nslow_count=%d\nprobe_samples=%s\n",
		s.Failures, s.Interval, s.LastProbe, s.Cooldown, s.Baseline, s.Slow, strings.Join(samples, ",")))
}

func (s State) Due(now int64) bool { return s.LastProbe == 0 || now-s.LastProbe >= s.Interval }

func (s *State) Record(now, elapsed int64, sampleOK bool, reason string) []string {
	old := s.Interval
	s.LastProbe = now
	median := int64(0)
	if sampleOK {
		s.Samples = append(s.Samples, elapsed)
		if len(s.Samples) > 6 {
			s.Samples = s.Samples[len(s.Samples)-6:]
		}
		if len(s.Samples) == 6 {
			ordered := slices.Clone(s.Samples)
			slices.Sort(ordered)
			median = (ordered[2] + ordered[3]) / 2
		}
	}
	threshold := max(s.Baseline+250, s.Baseline*3/2)
	if sampleOK && s.Interval > 30 {
		if elapsed > threshold {
			s.Slow++
		} else {
			s.Slow = 0
		}
		if s.Slow >= 3 || len(s.Samples) == 6 && median > threshold {
			sampleOK, reason = false, "latency_regression"
		}
	}
	if !sampleOK {
		s.Interval, s.Cooldown, s.Baseline, s.Slow, s.Samples = 30, now+600, 0, 0, nil
		if old != 30 {
			return []string{fmt.Sprintf("probe schedule rollback interval=%d->30 reason=%s cooldown=600s", old, reason)}
		}
		return nil
	}
	if len(s.Samples) == 6 && now >= s.Cooldown {
		if s.Interval == 30 {
			s.Baseline, s.Interval = median, 60
		} else if s.Interval == 60 && median <= threshold && s.Slow == 0 {
			s.Interval = 120
		}
		if old != s.Interval {
			s.Samples = nil
			return []string{fmt.Sprintf("probe schedule trial interval=%d->%d baseline_ms=%d median_ms=%d samples=6", old, s.Interval, s.Baseline, median)}
		}
		if s.Interval == 120 {
			s.Samples = nil
			return []string{fmt.Sprintf("probe schedule verified interval=120 baseline_ms=%d median_ms=%d samples=6", s.Baseline, median)}
		}
	}
	return nil
}

// Save preserves the previous state on write/rename failure and removes only
// the temporary file created by this writer. The caller holds the health lock.
func Save(path string, state State, rename func(string, string) error) error {
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("health state is not a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	temporary := path + ".tmp." + strconv.Itoa(os.Getpid())
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(state.Encode())
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return rename(temporary, path)
}
