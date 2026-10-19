package main

import (
	"net"
	"syscall"
	"testing"
)

func TestInheritedListenerUsesTheOriginalEndpointAndRejectsMismatch(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	file, err := listener.File()
	if err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Dup(int(file.Fd()))
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	inherited, err := inheritedListener(fd, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer inherited.Close()
	if inherited.Addr().String() != listener.Addr().String() {
		t.Fatal("listener endpoint changed")
	}
	// The parent retains its own descriptor until the session has stopped.
	if replacement, e := net.Listen("tcp4", listener.Addr().String()); e == nil {
		replacement.Close()
		t.Fatal("inherited endpoint became available for replacement")
	}
	file2, err := listener.File()
	if err != nil {
		t.Fatal(err)
	}
	fd, err = syscall.Dup(int(file2.Fd()))
	file2.Close()
	if err != nil {
		t.Fatal(err)
	}
	if other, err := inheritedListener(fd, "127.0.0.1:1"); err == nil {
		other.Close()
		t.Fatal("mismatched inherited endpoint accepted")
	}
}

func TestInheritedDescriptorIsNotAvailableToCheck(t *testing.T) {
	if err := command([]string{"check", "-c", "unused", "-listen-fd", "4"}); err == nil {
		t.Fatal("check accepted a listener descriptor")
	}
	if err := command([]string{"run", "-c", "unused", "-listen-fd", "0"}); err == nil {
		t.Fatal("standard descriptor accepted as listener")
	}
}
