package wiredguard

import (
	"errors"
	"fmt"
	"strings"
)

type PFSnapshot struct {
	Root, Interfaces, NAT string
	States, Wired         string
	Filters               map[string]string
	Translations          map[string]string
}

// ValidatePF deliberately accepts a small subset of live PF configurations.
// Loading a private anchor alone does not prove that the main ruleset reaches it.
func ValidatePF(p PFSnapshot, ownRules string) error {
	if ownRules != "" && p.Filters[Anchor] != ownRules {
		return errors.New("private PF anchor is missing from the reachable anchor inventory")
	}
	root := nonemptyLines(p.Root)
	// macOS includes its normalization anchor in `pfctl -sr`, before the
	// filter anchor. Accept that exact Apple rule without changing it.
	if len(root) == 2 && compact(root[0]) == "scrub-anchor com.apple/* all fragment reassemble" {
		root = root[1:]
	}
	if len(root) != 1 || compact(root[0]) != "anchor com.apple/* all" {
		return errors.New("PF main filter must contain only the existing com.apple/* anchor; refusing to replace global rules")
	}
	if p.Wired == "" || strings.Contains(strings.ToLower(p.Interfaces), "skip") || !strings.Contains(p.Interfaces, "lo0") || !strings.Contains(p.Interfaces, p.Wired) {
		return errors.New("PF interface coverage is unavailable or an interface is skipped")
	}
	if strings.TrimSpace(p.States) != "" {
		return errors.New("existing PF states cannot be attributed to the new GID; refusing to flush or reuse them")
	}
	checkNAT := func(text string) error {
		for _, line := range nonemptyLines(text) {
			fields := strings.Fields(compact(line))
			if len(fields) < 2 || (fields[0] != "nat-anchor" && fields[0] != "rdr-anchor" && fields[0] != "binat-anchor") || strings.Contains(" "+compact(line)+" ", " pass ") {
				return errors.New("PF translation or nat-pass rules may bypass socket ownership; configuration unsupported")
			}
		}
		return nil
	}
	if err := checkNAT(p.NAT); err != nil {
		return err
	}
	for anchor, rules := range p.Filters {
		if anchor == Anchor {
			if rules != ownRules {
				return errors.New("private PF anchor differs from the session ownership record")
			}
			continue
		}
		for _, line := range nonemptyLines(rules) {
			text := " " + compact(line) + " "
			for _, word := range []string{"quick", "route-to", "reply-to", "dup-to", "divert-to", "skip", "floating"} {
				if strings.Contains(text, " "+word+" ") {
					return fmt.Errorf("unsupported PF bypass or early termination in anchor %s", anchor)
				}
			}
			fields := strings.Fields(text)
			if len(fields) == 0 || (fields[0] != "block" && fields[0] != "anchor") {
				return fmt.Errorf("unrecognized PF filter in anchor %s", anchor)
			}
		}
	}
	for _, rules := range p.Translations {
		if err := checkNAT(rules); err != nil {
			return err
		}
	}
	return nil
}

func compact(text string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(text, "\"", "")), " ")
}
func nonemptyLines(text string) []string {
	var result []string
	for _, line := range strings.Split(text, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			result = append(result, line)
		}
	}
	return result
}

// PF may render a numeric UID as its account name. Only that exact account's
// name is accepted; all other words and the complete rule order must match.
func ValidateLoadedRules(actual string, s State, username string) error {
	rules, err := Rules(s)
	if err != nil {
		return err
	}
	got, want := nonemptyLines(actual), nonemptyLines(rules)
	if len(got) != len(want) {
		return errors.New("unexpected private PF rule count")
	}
	for i := range got {
		text := compact(got[i])
		text = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(" "+text+" ", " user = root ", " user = 0 "), " group = wheel ", " group = 0 "))
		if username != "" {
			text = strings.ReplaceAll(" "+text+" ", " user = "+username+" ", fmt.Sprintf(" user = %d ", s.UID))
			text = strings.TrimSpace(text)
		}
		if normalizeFlags(text) != normalizeFlags(compact(want[i])) {
			return fmt.Errorf("loaded PF rule %d does not match the complete expected rule", i+1)
		}
	}
	return nil
}

// macOS pfctl omits the explicit "flags any" when rendering a no-state rule.
// Other flag expressions remain significant and must still match exactly.
func normalizeFlags(text string) string {
	return strings.TrimSpace(strings.ReplaceAll(" "+text+" ", " flags any no state ", " no state "))
}
