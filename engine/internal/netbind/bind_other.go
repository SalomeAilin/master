//go:build !darwin

package netbind

import (
	"context"
	"errors"
	"syscall"
)

func Control(string) func(context.Context, string, string, syscall.RawConn) error {
	return func(context.Context, string, string, syscall.RawConn) error {
		return errors.New("macOS interface binding required")
	}
}
