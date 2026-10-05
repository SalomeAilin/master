//go:build !darwin || !cgo

package dnsservice

import (
	"errors"
	"os"
)

func SocketActivationAvailable() bool { return false }

func activate(string) ([]*os.File, error) {
	return nil, errors.New("native DNS requires macOS launchd socket activation; build with CGO_ENABLED=1")
}
