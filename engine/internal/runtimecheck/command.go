package runtimecheck

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// CommandError reports a command that exited with a non-zero status.
type CommandError struct {
	Args   []string
	Code   int
	Output string
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("%s exited with status %d: %s", strings.Join(e.Args, " "), e.Code, strings.TrimSpace(e.Output))
}

func ExitCode(err error) (int, bool) {
	var command *CommandError
	if errors.As(err, &command) {
		return command.Code, true
	}
	return 0, false
}

func Run(args ...string) (string, error) {
	return RunContext(context.Background(), 30*time.Second, args...)
}

func RunContext(ctx context.Context, limit time.Duration, args ...string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("missing command")
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	output, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	if ctx.Err() != nil {
		return string(output), fmt.Errorf("%s: %w", strings.Join(args, " "), ctx.Err())
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return string(output), &CommandError{Args: args, Code: exit.ExitCode(), Output: string(output)}
	}
	return string(output), err
}
