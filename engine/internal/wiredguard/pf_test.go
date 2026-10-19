package wiredguard

import (
	"strings"
	"testing"
)

func safePF() PFSnapshot {
	return PFSnapshot{Root: "anchor \"com.apple/*\" all\n", Interfaces: "en5\nlo0\nen1\n", Wired: "en5", NAT: "nat-anchor \"com.apple/*\" all\nrdr-anchor \"com.apple/*\" all\n", Filters: map[string]string{"com.apple": ""}, Translations: map[string]string{"com.apple": ""}}
}

func TestPFRequiresReachableExactPrivateAnchor(t *testing.T) {
	p := safePF()
	s := activeState()
	rules := Rules(s.UID, s.GID)
	if err := ValidatePF(p, ""); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePF(p, rules); err == nil {
		t.Fatal("missing private anchor accepted")
	}
	p.Filters[Anchor] = rules
	if err := ValidatePF(p, rules); err != nil {
		t.Fatal(err)
	}
	p.Root = "anchor \"com.local/*\" all\n"
	if err := ValidatePF(p, rules); err == nil {
		t.Fatal("unreachable anchor accepted")
	}
}

func TestPFAllowsOnlyTheStandardAppleNormalizationAnchor(t *testing.T) {
	p := safePF()
	p.Root = "scrub-anchor \"com.apple/*\" all fragment reassemble\n" + p.Root
	if err := ValidatePF(p, ""); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{
		"scrub all fragment reassemble\nanchor \"com.apple/*\" all\n",
		"scrub-anchor \"other/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n",
		p.Root + "anchor \"com.apple/*\" all\n",
	} {
		p.Root = root
		if err := ValidatePF(p, ""); err == nil {
			t.Fatal("unrecognized normalization or extra filters accepted", root)
		}
	}
}

func TestPFRejectsStatesSkipsPassesAndTranslationBypasses(t *testing.T) {
	for name, mutate := range map[string]func(*PFSnapshot){
		"floating state":              func(p *PFSnapshot) { p.States = "all tcp 192.0.2.1:50000 -> 198.51.100.1:443 ESTABLISHED:ESTABLISHED" },
		"bound old state":             func(p *PFSnapshot) { p.States = "en1 tcp 192.0.2.1:50000 -> 198.51.100.1:443 ESTABLISHED:ESTABLISHED" },
		"skip loopback":               func(p *PFSnapshot) { p.Interfaces += "lo0 (skip)\n" },
		"quick root":                  func(p *PFSnapshot) { p.Root = "pass out quick all\n" + p.Root },
		"quick child":                 func(p *PFSnapshot) { p.Filters["com.apple/early"] = "pass out quick all\n" },
		"new default floating states": func(p *PFSnapshot) { p.Filters["com.apple/late"] = "pass out all keep state\n" },
		"nat pass":                    func(p *PFSnapshot) { p.NAT += "nat pass on en1 from any to any -> (en1)\n" },
		"nested rdr": func(p *PFSnapshot) {
			p.Translations["com.apple/vendor"] = "rdr on lo0 proto tcp from any to any -> 127.0.0.1 port 17890\n"
		},
		"route to":       func(p *PFSnapshot) { p.Filters["com.apple/route"] = "block out route-to (en1 192.0.2.1) all\n" },
		"unknown filter": func(p *PFSnapshot) { p.Filters["com.apple/x"] = "mystery directive\n" },
	} {
		t.Run(name, func(t *testing.T) {
			p := safePF()
			mutate(&p)
			if err := ValidatePF(p, ""); err == nil {
				t.Fatal("unsafe PF configuration accepted")
			}
		})
	}
}

func TestLoadedRulesCannotAddAnAllowOrLoseCredentials(t *testing.T) {
	s := activeState()
	rules := Rules(s.UID, s.GID)
	if err := ValidateLoadedRules(rules, s, "example"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{rules + "pass out all\n", strings.ReplaceAll(rules, "group = 62000", "group = 20"), strings.Replace(rules, "flags any no state", "keep state", 1), strings.Replace(rules, "127.0.0.1 port = 17891", "127.0.0.1 port = 17890", 1), strings.Replace(rules, "user = 501 ", "", 1)} {
		if err := ValidateLoadedRules(bad, s, "example"); err == nil {
			t.Fatal("tampered PF barrier accepted", bad)
		}
	}
}

func TestPFOnlyRemovesKnownALTQDiagnostics(t *testing.T) {
	input := "No ALTQ support in kernel\nALTQ related functions disabled\nanchor \"com.apple/*\" all\n"
	if got := cleanPFOutput(input); got != "anchor \"com.apple/*\" all\n" {
		t.Fatal(got)
	}
	if got := cleanPFOutput("WARNING unknown state bypass\n"); !strings.Contains(got, "WARNING") {
		t.Fatal("unknown diagnostic removed")
	}
}

func TestHardwarePortMustBeWired(t *testing.T) {
	ports := "Hardware Port: Wi-Fi\nDevice: en0\n\nHardware Port: USB 10/100/1000 LAN\nDevice: en5\n"
	if IsEthernetHardware(ports, "en0") || !IsEthernetHardware(ports, "en5") || IsEthernetHardware(ports, "en9") {
		t.Fatal("wrong hardware selected")
	}
}

func TestMacOSCanonicalSevenRulesOmitFlagsAny(t *testing.T) {
	const canonical = `pass out quick on lo0 inet proto tcp from 127.0.0.1 to 127.0.0.1 port = 17891 user = 501 group = 62000 no state label "wired-app-loopback"
pass in quick on lo0 inet proto tcp from 127.0.0.1 to 127.0.0.1 port = 17891 user = 0 group = 0 no state label "wired-app-root-listener"
block drop in quick on lo0 inet proto tcp from 127.0.0.1 to 127.0.0.1 port = 17891 label "wired-app-deny-server"
pass out quick on lo0 inet proto tcp from 127.0.0.1 port = 17891 to 127.0.0.1 user = 0 group = 0 no state label "wired-app-server-reply"
pass in quick on lo0 inet proto tcp from 127.0.0.1 port = 17891 to 127.0.0.1 user = 501 group = 62000 no state label "wired-app-client-reply"
block drop out quick proto tcp all user = 501 group = 62000 label "wired-app-deny-tcp"
block drop out quick proto udp all user = 501 group = 62000 label "wired-app-deny-udp"
`
	if err := ValidateLoadedRules(canonical, activeState(), "example"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateLoadedRules(strings.Replace(canonical, "no state", "flags S/SA no state", 1), activeState(), "example"); err == nil {
		t.Fatal("non-any TCP flags accepted")
	}
}
