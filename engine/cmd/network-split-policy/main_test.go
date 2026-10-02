package main

import (
	"bytes"
	"strings"
	"testing"
)

var repositoryPolicy = []string{"-policy-file", "../../../config/china_ip_list.txt", "-policy-file", "../../../config/domestic_extra_routes.txt"}

func TestSingleAddressExitStatus(t *testing.T) {
	for ip, want := range map[string]int{"223.5.5.5": 0, "8.8.8.8": 1, "127.0.0.1": 1, "999.1.1.1": 1} {
		if got := run(append(repositoryPolicy, ip), nil, &bytes.Buffer{}, &bytes.Buffer{}); got != want {
			t.Errorf("%s: exit %d, want %d", ip, got, want)
		}
	}
}

func TestBatchKeepsOnlyAuthorizedAnswersInOrder(t *testing.T) {
	var output bytes.Buffer
	input := strings.NewReader("8.8.8.8\n223.5.5.5\n127.0.0.1\n 119.29.29.29 \r\n\n")
	if code := run(repositoryPolicy, input, &output, &bytes.Buffer{}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if output.String() != "223.5.5.5\n119.29.29.29\n" {
		t.Fatalf("output %q", output.String())
	}
}

func TestMissingPolicyAuthorizesNothing(t *testing.T) {
	missing := []string{"-policy-file", t.TempDir() + "/missing.txt"}
	var output bytes.Buffer
	if run(append(missing, "223.5.5.5"), nil, &output, &bytes.Buffer{}) != 1 {
		t.Fatal("missing policy authorized a single address")
	}
	if run(missing, strings.NewReader("223.5.5.5\n"), &output, &bytes.Buffer{}) != 0 || output.Len() != 0 {
		t.Fatalf("missing policy authorized a batch answer: %q", output.String())
	}
}

func TestExtraArgumentsAreRejected(t *testing.T) {
	if run([]string{"1.1.1.1", "2.2.2.2"}, nil, &bytes.Buffer{}, &bytes.Buffer{}) != 2 {
		t.Fatal("ambiguous invocation accepted")
	}
}
