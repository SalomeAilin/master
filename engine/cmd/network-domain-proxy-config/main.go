// Command network-domain-proxy-config writes the engine configuration built
// from the repository's routing policy. It reads policy files only; it does
// not download data, install files, change routes or start services.
package main

import (
	"flag"
	"fmt"
	"os"

	"network-owned-engine/internal/proxyconfig"
)

func main() {
	flags := flag.NewFlagSet("network-domain-proxy-config", flag.ExitOnError)
	policyDir := flags.String("policy-dir", "", "routing policy directory (default: nearest config/ above the working directory)")
	rules := flags.String("rules-directory", "", "rule seed directory (default "+proxyconfig.RulesDirectory+")")
	cache := flags.String("cache-path", "", "rule cache directory (default "+proxyconfig.CacheDirectory+")")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "usage: network-domain-proxy-config [flags] output.json")
		flags.PrintDefaults()
	}
	flags.Parse(os.Args[1:])
	if flags.NArg() != 1 {
		flags.Usage()
		os.Exit(2)
	}
	if err := write(flags.Arg(0), *policyDir, *rules, *cache); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func write(output, policyDir, rules, cache string) error {
	if policyDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		if policyDir, err = proxyconfig.FindPolicyDir(wd); err != nil {
			return err
		}
	}
	config, err := proxyconfig.Build(policyDir, rules, cache)
	if err != nil {
		return err
	}
	data, err := proxyconfig.Encode(config)
	if err != nil {
		return err
	}
	return os.WriteFile(output, data, 0644)
}
