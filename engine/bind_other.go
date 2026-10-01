//go:build !darwin

package main

import (
	"context"
	"errors"
	"net"
)

func interfaceDial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("this engine requires macOS interface binding")
}
