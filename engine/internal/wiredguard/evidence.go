package wiredguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

const recentProxyLogLimit = 128 << 10

type evidenceReport struct {
	State                 State     `json:"state"`
	Started               time.Time `json:"sample_started_at"`
	Finished              time.Time `json:"sample_finished_at"`
	NettopCSV             string    `json:"nettop_csv"`
	RecentLog             string    `json:"recent_proxy_log"`
	BarrierVerified       bool      `json:"barrier_verified_before_and_after"`
	ProxyIdentityVerified bool      `json:"proxy_identity_verified_before_and_after"`
}

type evidenceOperations struct {
	verify   func(context.Context, State) error
	identity func(int) (Identity, error)
	command  func(context.Context, string, ...string) (string, error)
	log      func(string, uint32, uint32) (string, error)
}

func (n *Native) Evidence(ctx context.Context, s State) (evidenceReport, error) {
	return collectEvidence(ctx, s, evidenceOperations{n.Verify, nativeIdentity, command, readRecentProxyLog})
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
	report.State, report.Started = s, time.Now()
	sampleCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	csv, sampleErr := operations.command(sampleCtx, "", "/usr/bin/nettop", "-n", "-x", "-p", strconv.Itoa(s.Proxy.PID), "-L", "3", "-s", "2")
	cancel()
	log, logErr := operations.log(s.Cache, 0, s.Proxy.UID)
	// A failed sample still checks the barrier and PID before returning. Partial
	// output is never presented as a verified observation.
	afterErr := verify()
	if err := errors.Join(sampleErr, logErr, afterErr); err != nil {
		return evidenceReport{}, fmt.Errorf("evidence sample was not verified: %w", err)
	}
	report.Finished, report.NettopCSV, report.RecentLog = time.Now(), csv, log
	report.BarrierVerified, report.ProxyIdentityVerified = true, true
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
