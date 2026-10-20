package wiredguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

const recentProxyLogLimit = 128 << 10

type evidenceReport struct {
	State                 State            `json:"state"`
	Started               time.Time        `json:"sample_started_at"`
	Finished              time.Time        `json:"sample_finished_at"`
	NettopCSV             string           `json:"nettop_csv"`
	RecentLog             string           `json:"recent_proxy_log"`
	BarrierVerified       bool             `json:"barrier_verified_before_and_after"`
	ProxyIdentityVerified bool             `json:"proxy_identity_verified_before_and_after"`
	SampledProcesses      []Identity       `json:"sampled_processes"`
	ExitedProcesses       []Identity       `json:"exited_sampled_processes,omitempty"`
	NewProcesses          []Identity       `json:"new_controlled_processes_not_sampled,omitempty"`
	ProcessSetStable      bool             `json:"sampled_process_set_stable"`
	PFLabelsBefore        string           `json:"pf_labels_before"`
	PFLabelsAfter         string           `json:"pf_labels_after"`
	SocketCredentials     string           `json:"original_socket_credentials"`
	ObservationPersisted  bool             `json:"socket_observation_persisted"`
	UnresolvedBefore      []UnresolvedPath `json:"unresolved_paths_before,omitempty"`
	UnresolvedAfter       []UnresolvedPath `json:"unresolved_paths_after,omitempty"`
}

type evidenceOperations struct {
	verify   func(context.Context, State) error
	identity func(int) (Identity, error)
	command  func(context.Context, string, ...string) (string, error)
	log      func(string, uint32, uint32) (string, error)
	inspect  func(context.Context, *State) (Snapshot, error)
	labels   func(context.Context) (string, error)
}

func (n *Native) Evidence(ctx context.Context, s State) (evidenceReport, error) {
	return collectEvidence(ctx, s, evidenceOperations{verify: n.Verify, identity: nativeIdentity, command: command, log: readRecentProxyLog, inspect: n.Inspect, labels: func(ctx context.Context) (string, error) {
		text, err := pf(ctx, "", "-a", Anchor, "-s", "labels")
		if len(text) > recentProxyLogLimit {
			return "", errors.New("private PF label output exceeds 128 KiB")
		}
		return text, err
	}})
}

func evidenceTargets(s State, snap Snapshot) ([]Identity, error) {
	if _, _, err := Ownership(s, snap); err != nil {
		return nil, err
	}
	targets := []Identity{*s.Proxy}
	seen := map[int]bool{s.Proxy.PID: true}
	for _, process := range snap.Processes {
		if sessionHolder(s, process) && !seen[process.PID] {
			seen[process.PID] = true
			targets = append(targets, process)
		}
	}
	if len(targets) > 64 {
		return nil, errors.New("too many controlled processes for a bounded evidence sample")
	}
	slices.SortFunc(targets[1:], func(a, b Identity) int { return a.PID - b.PID })
	return targets, nil
}

func collectEvidence(ctx context.Context, s State, operations evidenceOperations) (evidenceReport, error) {
	var report evidenceReport
	if err := s.Validate(); err != nil {
		return report, err
	}
	if s.Proxy == nil || s.Cache == "" {
		return report, errors.New("session has no recorded temporary proxy or private log")
	}
	verify := func() error {
		identity, err := operations.identity(s.Proxy.PID)
		if err == nil && !SameProcess(identity, *s.Proxy) {
			err = errors.New("temporary proxy identity changed")
		}
		if err != nil {
			err = fmt.Errorf("temporary proxy identity: %w", err)
		}
		return errors.Join(err, operations.verify(ctx, s))
	}
	if err := verify(); err != nil {
		return report, fmt.Errorf("before evidence sample: %w", err)
	}
	before, err := operations.inspect(ctx, &s)
	if err != nil {
		return report, err
	}
	targets, err := evidenceTargets(s, before)
	if err != nil {
		return report, err
	}
	labelsBefore, err := operations.labels(ctx)
	if err != nil || len(labelsBefore) > recentProxyLogLimit {
		return report, errors.Join(errors.New("cannot read bounded private PF label counters before sampling"), err)
	}
	report.State, report.Started = s, time.Now()
	args := []string{"/usr/bin/nettop", "-n", "-x"}
	for _, target := range targets {
		args = append(args, "-p", strconv.Itoa(target.PID))
	}
	args = append(args, "-L", "3", "-s", "2")
	sampleCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	csv, sampleErr := operations.command(sampleCtx, "", args...)
	cancel()
	log, logErr := operations.log(s.Cache, 0, s.Proxy.UID)
	labelsAfter, labelsErr := operations.labels(ctx)
	if len(labelsAfter) > recentProxyLogLimit {
		labelsErr = errors.New("private PF label output exceeds 128 KiB")
	}
	// A failed sample still checks the barrier and PID before returning. Partial
	// output is never presented as a verified observation.
	afterErr := verify()
	after, inspectErr := operations.inspect(ctx, &s)
	afterTargets, targetsErr := evidenceTargets(s, after)
	for _, target := range targets[1:] {
		current, identityErr := operations.identity(target.PID)
		if os.IsNotExist(identityErr) {
			report.ExitedProcesses = append(report.ExitedProcesses, target)
		} else if identityErr != nil || !SameProcess(target, current) {
			if identityErr == nil {
				identityErr = errors.New("process identity changed")
			}
			afterErr = errors.Join(afterErr, fmt.Errorf("sampled PID %d changed or cannot be checked: %w", target.PID, identityErr))
		}
	}
	for _, target := range afterTargets {
		if !slices.ContainsFunc(targets, func(before Identity) bool { return SameProcess(before, target) }) {
			report.NewProcesses = append(report.NewProcesses, target)
		}
	}
	if err := errors.Join(sampleErr, logErr, labelsErr, afterErr, inspectErr, targetsErr); err != nil {
		return evidenceReport{}, fmt.Errorf("evidence sample was not verified: %w", err)
	}
	report.Finished, report.NettopCSV, report.RecentLog = time.Now(), csv, log
	report.BarrierVerified, report.ProxyIdentityVerified = true, true
	report.SampledProcesses, report.PFLabelsBefore, report.PFLabelsAfter = targets, labelsBefore, labelsAfter
	report.ProcessSetStable = len(report.ExitedProcesses) == 0 && len(report.NewProcesses) == 0
	report.SocketCredentials, report.ObservationPersisted = "unknown: libproc does not expose so_cred", s.SocketObservationStarted
	report.UnresolvedBefore, report.UnresolvedAfter = before.UnresolvedPaths, after.UnresolvedPaths
	return report, nil
}

func readRecentProxyLog(path string, parentUID, workerUID uint32) (string, error) {
	parentFD, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(parentFD)
	var stat unix.Stat_t
	if err = unix.Fstat(parentFD, &stat); err != nil {
		return "", err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != parentUID || stat.Mode&07777 != 0711 {
		return "", errors.New("unsafe root-owned proxy cache parent")
	}
	workerFD, err := unix.Openat(parentFD, "worker", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(workerFD)
	if err = unix.Fstat(workerFD, &stat); err != nil {
		return "", err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != workerUID || stat.Mode&07777 != 0700 {
		return "", errors.New("unsafe private proxy worker cache")
	}
	// O_NONBLOCK avoids waiting on a substituted FIFO before fstat rejects it.
	logFD, err := unix.Openat(workerFD, "proxy.log", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(logFD), "private proxy log")
	defer file.Close()
	if err = unix.Fstat(logFD, &stat); err != nil {
		return "", err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != workerUID || stat.Mode&07777 != 0600 || stat.Nlink != 1 || stat.Size < 0 {
		return "", errors.New("unsafe private proxy log")
	}
	start := max(int64(0), stat.Size-recentProxyLogLimit)
	data, err := io.ReadAll(io.NewSectionReader(file, start, stat.Size-start))
	return string(data), err
}
