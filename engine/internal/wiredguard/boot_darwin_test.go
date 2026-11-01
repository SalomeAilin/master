package wiredguard

import "testing"

func TestKernelBootIdentityIsStable(t *testing.T) {
	id, started, err := bootIdentity()
	if err != nil || !validBootID(id) || started <= 0 {
		t.Fatalf("kernel boot identity unavailable: %v", err)
	}
	secondID, secondStarted, err := bootIdentity()
	if err != nil || id != secondID || started != secondStarted {
		t.Fatalf("kernel boot identity changed during inspection: %v", err)
	}
}
