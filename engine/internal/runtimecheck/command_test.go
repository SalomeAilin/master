package runtimecheck

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCommandFixture(t *testing.T) {
	switch os.Args[len(os.Args)-1] {
	case "command-fail-fixture":
		fmt.Fprintln(os.Stderr, "fixture failure")
		os.Exit(5)
	case "command-timeout-fixture":
		time.Sleep(time.Hour)
	}
}

func TestCommandFailureAndTimeoutArePreserved(t *testing.T) {
	args := []string{os.Args[0], "-test.run=^TestCommandFixture$", "command-fail-fixture"}
	out, err := RunContext(context.Background(), 5*time.Second, args...)
	if code, ok := ExitCode(err); !ok || code != 5 || !strings.Contains(out, "fixture failure") {
		t.Fatal(out, err)
	}
	args[len(args)-1] = "command-timeout-fixture"
	start := time.Now()
	_, err = RunContext(context.Background(), 100*time.Millisecond, args...)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
		t.Fatal("timed-out child was not reaped", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunContext(ctx, time.Second, args...); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}
