package wiredguard

import (
	"errors"
	"strings"

	"golang.org/x/sys/unix"
)

func bootIdentity() (string, int64, error) {
	id, err := unix.Sysctl("kern.bootsessionuuid")
	if err != nil {
		return "", 0, err
	}
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return "", 0, err
	}
	id = strings.ToUpper(strings.TrimSpace(id))
	if id == "" || tv.Sec <= 0 {
		return "", 0, errors.New("invalid kernel boot identity")
	}
	return id, tv.Sec*1000000 + int64(tv.Usec), nil
}
