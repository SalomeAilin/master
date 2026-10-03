// Package healthcheck performs the existing one-shot domestic health check
// without a shell, curl, awk or grep. Only macOS route/service APIs are invoked.
package healthcheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

const ProbeURL = "https://live.douyin.com/"
const GuardService = "system/com.local.network-split-guard"

type Result struct {
	Status            int
	ElapsedMS         int64
	RemoteIP, LocalIP string
	Err               error
}

type Outcome struct {
	Result
	Healthy, SampleOK, Drift bool
	Reason                   string
}

type Runner struct {
	StatePath, LogPath, ConfigPath string
	Now                            func() time.Time
	Run                            func(...string) (string, error)
	Probe                          func(context.Context) Result
	Route                          func(string) (bool, error)
}

func Probe(ctx context.Context, target string) Result {
	started := time.Now()
	result := Result{}
	var mu sync.Mutex
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		mu.Lock()
		defer mu.Unlock()
		result.RemoteIP, _, _ = net.SplitHostPort(info.Conn.RemoteAddr().String())
		result.LocalIP, _, _ = net.SplitHostPort(info.Conn.LocalAddr().String())
	}}
	ctx, cancel := context.WithTimeout(httptrace.WithClientTrace(ctx, trace), 10*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 4 * time.Second,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", address)
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) >= 10 || via[0].URL.Scheme == "https" && request.URL.Scheme != "https" {
			return errors.New("unsafe health redirect")
		}
		return nil
	}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err == nil {
		request.Header.Set("User-Agent", "network-split-health/1")
		var response *http.Response
		response, err = client.Do(request)
		if err == nil {
			result.Status = response.StatusCode
			var size int64
			size, err = io.Copy(io.Discard, io.LimitReader(response.Body, (4<<20)+1))
			response.Body.Close()
			if size > 4<<20 {
				err = errors.New("health response exceeds 4 MiB")
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	result.Err, result.ElapsedMS = err, time.Since(started).Round(time.Millisecond).Milliseconds()
	return result
}

func (r *Runner) wiredRoute(ip string) (bool, error) {
	address, err := netip.ParseAddr(ip)
	if err != nil || !address.Is4() {
		return false, errors.New("invalid probe address")
	}
	file, err := os.Open(r.ConfigPath)
	if err != nil {
		return false, err
	}
	defer file.Close()
	var config struct {
		Domestic struct {
			Interface string `json:"interface"`
		} `json:"domestic"`
	}
	if err := json.NewDecoder(io.LimitReader(file, 4<<20)).Decode(&config); err != nil {
		return false, err
	}
	iface := config.Domestic.Interface
	if iface == "" || strings.ContainsAny(iface, " \t\r\n") {
		return false, errors.New("missing domestic interface")
	}
	expected, err := r.Run("/sbin/route", "-n", "get", "-ifscope", iface, "default")
	if err != nil {
		return false, err
	}
	gateway, expectedInterface := routeFields(expected)
	if gateway == "" || expectedInterface != iface {
		return false, errors.New("wired gateway is unavailable")
	}
	actual, err := r.Run("/sbin/route", "-n", "get", address.String())
	if err != nil {
		return false, err
	}
	actualGateway, actualInterface := routeFields(actual)
	if actualGateway == "" || actualInterface == "" {
		return false, errors.New("incomplete route evidence")
	}
	return actualGateway == gateway && actualInterface == iface, nil
}

func routeFields(raw string) (gateway, iface string) {
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		switch key {
		case "gateway":
			gateway = strings.TrimSpace(value)
		case "interface":
			iface = strings.TrimSpace(value)
		}
	}
	return
}

func (r *Runner) Check(ctx context.Context) Outcome {
	probe := r.Probe
	if probe == nil {
		probe = func(ctx context.Context) Result { return Probe(ctx, ProbeURL) }
	}
	result := probe(ctx)
	outcome := Outcome{Result: result, Reason: "ok"}
	if result.RemoteIP != "" {
		route := r.Route
		if route == nil {
			route = r.wiredRoute
		}
		ok, err := route(result.RemoteIP)
		if err != nil {
			outcome.Reason = "route_check_failed"
			outcome.Err = err
			return outcome
		}
		if !ok {
			outcome.Reason, outcome.Drift = "route_drift", true
			return outcome
		}
	}
	switch {
	case result.Err != nil:
		outcome.Reason = "probe_failed"
	case result.RemoteIP == "":
		outcome.Reason = "missing_remote_ip"
	case !(result.Status >= 200 && result.Status < 400 || result.Status == 401 || result.Status == 403):
		outcome.Reason = fmt.Sprintf("http_%d", result.Status)
	case result.ElapsedMS < 0 || result.ElapsedMS > 10000:
		outcome.Reason = "invalid_timing"
	case result.ElapsedMS > 4000:
		outcome.Reason = "slow_probe"
	default:
		outcome.Healthy = true
		outcome.SampleOK = result.Status >= 200 && result.Status < 400
		if !outcome.SampleOK {
			outcome.Reason = fmt.Sprintf("http_%d", result.Status)
		}
	}
	return outcome
}

func (r *Runner) Logf(format string, args ...any) error {
	fd, err := syscall.Open(r.LogPath, syscall.O_WRONLY|syscall.O_APPEND|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), r.LogPath)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("unsafe health log")
	}
	_, err = fmt.Fprintf(file, "%s %s\n", r.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
	return err
}

func (r *Runner) RunOnce(ctx context.Context) error {
	now := r.Now().Unix()
	state := Initial()
	if saved, err := Read(r.StatePath, now); err == nil {
		state = saved
	} else if !os.IsNotExist(err) && !errors.Is(err, ErrInvalidState) {
		return err
	}
	if !state.Due(now) {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	outcome := r.Check(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, line := range state.Record(now, outcome.ElapsedMS, outcome.SampleOK, outcome.Reason) {
		if err := r.Logf("%s", line); err != nil {
			return err
		}
	}
	if outcome.Healthy {
		if state.Failures > 0 {
			if err := r.Logf("recovered backend=go ip=%s local_ip=%s http=%d time_ms=%d prior_failures=%d", outcome.RemoteIP, outcome.LocalIP, outcome.Status, outcome.ElapsedMS, state.Failures); err != nil {
				return err
			}
		}
		state.Failures = 0
	} else {
		state.Failures = min(state.Failures+1, 1000000)
		if err := r.Logf("unhealthy backend=go ip=%s local_ip=%s reason=%s http=%d time_ms=%d failures=%d", outcome.RemoteIP, outcome.LocalIP, outcome.Reason, outcome.Status, outcome.ElapsedMS, state.Failures); err != nil {
			return err
		}
		if outcome.Drift {
			if _, err := r.Run("/bin/launchctl", "kickstart", GuardService); err != nil {
				if err := r.Logf("route recovery request failed service=%s; no direct retry", GuardService); err != nil {
					return err
				}
			}
		}
	}
	return Save(r.StatePath, state, os.Rename)
}
