//go:build !darwin || !cgo

package wiredguard

import (
	"context"
	"errors"
)

func nativeSnapshot(context.Context, uint32, *State) (Snapshot, error) {
	return Snapshot{}, errors.New("wired-app requires a CGO-enabled macOS build for process and socket ownership")
}

func nativeIdentity(int) (Identity, error) {
	return Identity{}, errors.New("wired-app requires a CGO-enabled macOS build")
}
