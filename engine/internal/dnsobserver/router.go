package dnsobserver

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// CommandFunc runs a program and returns its output and exit status. Its error
// is reserved for a program that could not start or did not finish in time; a
// non-zero exit status alone is not an error.
type CommandFunc func(timeout time.Duration, name string, args ...string) (stdout, stderr string, code int, err error)

// RunCommand is the production CommandFunc.
func RunCommand(timeout time.Duration, name string, args ...string) (string, string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	command := exec.CommandContext(ctx, name, args...)
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if ctx.Err() != nil {
		return stdout.String(), stderr.String(), -1, ctx.Err()
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return stdout.String(), stderr.String(), exit.ExitCode(), nil
	}
	return stdout.String(), stderr.String(), 0, err
}

// Router binds authorized addresses to the Ethernet gateway with host routes.
type Router struct {
	Policy    interface{ Allowed(string) bool }
	Command   CommandFunc
	Log       *Logger
	Gateway   string
	Interface string
}

// Bind enforces the address policy before any route lookup or change.
func (r *Router) Bind(domain, ip string) {
	if !r.Policy.Allowed(ip) || r.ethernet(ip) {
		return
	}
	if _, _, _, err := r.Command(time.Second, "/sbin/route", "-n", "delete", "-host", ip); err != nil {
		r.Log.Error("route command failed domain=%s ip=%s", domain, ip)
		return
	}
	_, stderr, code, err := r.Command(time.Second, "/sbin/route", "-n", "add", "-host", ip, r.Gateway, "-ifp", r.Interface)
	if err != nil {
		r.Log.Error("route command failed domain=%s ip=%s", domain, ip)
		return
	}
	if r.ethernet(ip) {
		r.Log.Info("route bound domain=%s ip=%s", domain, ip)
	} else {
		r.Log.Error("route bind failed domain=%s ip=%s exit=%d error=%s", domain, ip, code, strings.TrimSpace(stderr))
	}
}

func (r *Router) ethernet(ip string) bool {
	stdout, _, _, err := r.Command(time.Second, "/sbin/route", "-n", "get", ip)
	return err == nil && strings.Contains(stdout, "gateway: "+r.Gateway) && strings.Contains(stdout, "interface: "+r.Interface)
}
