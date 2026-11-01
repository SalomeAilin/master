//go:build !darwin

package wiredguard

import "errors"

func bootIdentity() (string, int64, error) {
	return "", 0, errors.New("boot identity is only supported on macOS")
}
