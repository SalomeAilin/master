package deploy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"network-owned-engine/internal/dnsservice"
	"network-owned-engine/internal/service"
)

func (d *Deployer) nativePreflight(c service.Config) (resultErr error) {
	p, err := dnsservice.Load(c.Routes.DNSConfig)
	if err != nil {
		return err
	}
	if p.Port != 53 || len(p.Listen) != 2 || p.Listen[0].String() != "127.0.0.1" || p.Listen[1].String() != c.Routes.DNS {
		return errors.New("native DNS migration must preserve the two installed listeners")
	}
	dir, err := os.MkdirTemp(d.BackupParent, "network-native-dns-preflight.")
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if !cleanup {
			resultErr = errors.Join(resultErr, fmt.Errorf("DNS preflight files retained for a worker that could not be stopped: %s", dir))
			return
		}
		if err := os.RemoveAll(dir); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	if err := os.Chmod(dir, 0o755); err != nil {
		return err
	}
	var port int
	for attempt := 0; attempt < 10; attempt++ {
		tcp, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return err
		}
		udp, err := net.ListenPacket("udp4", tcp.Addr().String())
		port = tcp.Addr().(*net.TCPAddr).Port
		tcp.Close()
		if err == nil {
			udp.Close()
			break
		}
		port = 0
	}
	if port == 0 {
		return errors.New("no isolated DNS port available")
	}
	p.Port = port
	p.Listen = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	p.QueryLog = filepath.Join(dir, "query.log")
	if err := os.WriteFile(p.QueryLog, nil, 0o660); err != nil {
		return err
	}
	nobody, err := lookupUser("nobody")
	if err != nil {
		return err
	}
	if err := d.Chown(p.QueryLog, nobody, 0); err != nil {
		return err
	}
	policy := filepath.Join(dir, "policy.conf")
	if err := os.WriteFile(policy, p.Encode(), 0o644); err != nil {
		return err
	}
	if err := os.Chmod(policy, 0o644); err != nil {
		return err
	}
	startup := filepath.Join(dir, "startup.log")
	if err := os.WriteFile(startup, nil, 0o600); err != nil {
		return err
	}
	if err := d.Chown(startup, nobody, 0); err != nil {
		return err
	}
	label := "com.local.network-split-dns-preflight." + filepath.Base(dir)
	definition := map[string]any{"Label": label, "UserName": "nobody", "RunAtLoad": true, "KeepAlive": false, "ExitTimeOut": 10,
		"StandardOutPath": startup, "StandardErrorPath": startup,
		"ProgramArguments": []string{filepath.Join(d.Root, EngineName), "worker", "dns", "-policy", policy, "-wired-interface", c.Routes.WiredInterface, "-wifi-interface", c.Routes.WiFiInterface}, "Sockets": p.SocketDefinition()}
	body, err := service.Plist(definition)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, label+".plist")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return err
	}
	job := installedJob{Domain: "system", Label: label, Path: path, Program: filepath.Join(d.Root, EngineName)}
	defer func() {
		if err := d.stopInstalledJob(job); err != nil {
			cleanup = false
			resultErr = errors.Join(resultErr, fmt.Errorf("DNS preflight cleanup: %w", err))
		}
	}()
	if err := d.bootstrapJob(job); err != nil {
		return err
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if err := d.probeNativeDNS(address); err != nil {
		if f, e := os.Open(startup); e == nil {
			b, _ := io.ReadAll(io.LimitReader(f, 8192))
			f.Close()
			if len(b) > 0 {
				return fmt.Errorf("%w; candidate output: %s", err, strings.TrimSpace(string(b)))
			}
		}
		return err
	}
	current, err := d.inspectInstalledJob(job)
	if err != nil || current.PID <= 0 {
		return errors.New("native DNS preflight worker is not running")
	}
	identity, err := d.Run("/bin/ps", "-p", strconv.Itoa(current.PID), "-o", "user=")
	if err != nil || strings.TrimSpace(identity) != "nobody" {
		return errors.New("native DNS preflight worker is not nobody")
	}
	fmt.Fprintf(d.Out, "Native DNS candidate pid=%d user=nobody listener=%s\n", current.PID, address)
	fmt.Fprintln(d.Out, "Native DNS preflight accepted: nobody worker, UDP/TCP, domestic/foreign DNS, AAAA filtering and negative answers")
	return nil
}

func (d *Deployer) probeNativeDNS(address string) error {
	for _, network := range []string{"udp4", "tcp4"} {
		client := &dns.Client{Net: network, Timeout: 8 * time.Second}
		for _, test := range []struct {
			name   string
			kind   uint16
			code   int
			answer bool
		}{{"localhost.", dns.TypeA, 0, true}, {"www.douyin.com.", dns.TypeA, 0, true}, {"github.com.", dns.TypeA, 0, true}, {"github.com.", dns.TypeAAAA, 0, false}, {"native-dns-preflight.invalid.", dns.TypeA, dns.RcodeNameError, false}} {
			q := new(dns.Msg)
			q.SetQuestion(test.name, test.kind)
			m, _, err := client.ExchangeContext(d.Context, q, address)
			if err != nil || m == nil {
				return fmt.Errorf("native DNS preflight %s %s: %w", network, test.name, err)
			}
			if m.Rcode != test.code {
				return fmt.Errorf("native DNS preflight %s returned rcode %d", test.name, m.Rcode)
			}
			found := false
			for _, rr := range m.Answer {
				if rr.Header().Rrtype == dns.TypeAAAA {
					return errors.New("native DNS returned a filtered AAAA record")
				}
				if rr.Header().Rrtype == dns.TypeA {
					found = true
				}
			}
			if test.answer && !found {
				return fmt.Errorf("native DNS preflight lacked A data: %s", test.name)
			}
		}
	}
	return nil
}
