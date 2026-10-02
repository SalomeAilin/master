// Command network-split-policy authorizes DNS answers for Ethernet host routes.
//
// With one address argument it exits 0 when the address is authorized and 1
// otherwise. Without arguments it reads one address per line from standard
// input and prints only the authorized ones, so a route guard can filter a
// whole DNS answer batch in one call. A missing or malformed policy authorizes
// nothing.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"network-owned-engine/internal/policy"
)

type fileList []string

func (f *fileList) String() string     { return strings.Join(*f, ",") }
func (f *fileList) Set(v string) error { *f = append(*f, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(arguments []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("network-split-policy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var files fileList
	flags.Var(&files, "policy-file", "address list used instead of the production lists (repeatable)")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if len(files) == 0 {
		files = policy.Files
	}
	p := policy.New(files...)
	switch flags.NArg() {
	case 1:
		if p.Allowed(flags.Arg(0)) {
			return 0
		}
		return 1
	case 0:
		scanner := bufio.NewScanner(stdin)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		output := bufio.NewWriter(stdout)
		for scanner.Scan() {
			if value := strings.TrimFunc(scanner.Text(), isSpace); p.Allowed(value) {
				fmt.Fprintln(output, value)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if output.Flush() != nil {
			return 1
		}
		return 0
	}
	fmt.Fprintln(stderr, "usage: network-split-policy [-policy-file path]... [address]")
	return 2
}

// isSpace matches Python's str.isspace, which the batch reader used to strip.
func isSpace(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) }
