// Command network-split-dns-event-route-agent observes dnsmasq replies and
// promptly binds domestic CDN addresses to Ethernet. It never proxies DNS; if
// it stops, dnsmasq keeps resolving and the route guard remains the fallback.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"network-owned-engine/internal/dnsobserver"
	"network-owned-engine/internal/policy"
)

const (
	queryLog     = "/var/log/dnsmasq-network-split-query.log"
	dnsmasqConf  = "/usr/local/etc/dnsmasq-network-split.conf"
	agentLog     = "/var/log/network-split-dns-event-route-agent.log"
	ethGateway   = "192.168.1.1"
	ethInterface = "en0"
)

func main() {
	check := flag.Bool("check", false, "verify the dnsmasq configuration and address policy, then exit")
	flag.Parse()
	if *check {
		suffixes, err := dnsobserver.LoadSuffixes(dnsmasqConf)
		if err == nil && !policy.New(policy.Files...).Allowed("223.5.5.5") {
			err = fmt.Errorf("address policy rejects 223.5.5.5")
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("ok suffixes=%d\n", len(suffixes))
		return
	}
	log := dnsobserver.NewLogger(agentLog)
	defer log.Close()
	router := &dnsobserver.Router{Policy: policy.New(policy.Files...), Command: dnsobserver.RunCommand,
		Log: log, Gateway: ethGateway, Interface: ethInterface}
	follower := &dnsobserver.Follower{LogPath: queryLog, ConfigPath: dnsmasqConf, MaxBytes: dnsobserver.MaxQueryLogBytes,
		Correlator: dnsobserver.NewCorrelator(nil, router.Bind), Log: log, Sleep: time.Sleep}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := follower.Run(ctx); err != nil {
		log.Error("startup failed error=%v", err)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
