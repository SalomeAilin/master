//go:build darwin && cgo

package dnsservice

/*
#include <launch.h>
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

func SocketActivationAvailable() bool { return true }

func activate(name string) ([]*os.File, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var descriptors *C.int
	var count C.size_t
	if code := C.launch_activate_socket(cname, &descriptors, &count); code != 0 {
		return nil, syscall.Errno(code)
	}
	defer C.free(unsafe.Pointer(descriptors))
	if count == 0 || count > 8 || descriptors == nil {
		return nil, errors.New("unexpected launchd socket count")
	}
	files := make([]*os.File, 0, int(count))
	for _, fd := range unsafe.Slice(descriptors, int(count)) {
		files = append(files, os.NewFile(uintptr(fd), name))
	}
	return files, nil
}
