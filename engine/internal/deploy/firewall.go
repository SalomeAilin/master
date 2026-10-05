package deploy

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const firewallTool = "/usr/libexec/ApplicationFirewall/socketfilterfw"

// Read the explicit allowlist: --getappblocked also says "permitted" for an
// absent entry and cannot preserve that distinction during rollback.
func (d *Deployer) firewallStates(paths []string) (map[string]string, error) {
	out, err := d.Run(firewallTool, "--listapps")
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	for _, path := range paths {
		result[path] = "absent"
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	prefix := "Total number of apps = "
	if len(lines) == 0 || !strings.HasPrefix(lines[0], prefix) {
		return nil, errors.New("unrecognized firewall inventory")
	}
	want, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(lines[0], prefix)))
	if err != nil || want < 0 {
		return nil, errors.New("invalid firewall inventory count")
	}
	seen := 0
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		index, path, ok := strings.Cut(line, " : ")
		n, parseErr := strconv.Atoi(index)
		if !ok || parseErr != nil || n != seen+1 || i+1 >= len(lines) {
			return nil, errors.New("incomplete firewall inventory")
		}
		i++
		var state string
		switch strings.TrimSpace(lines[i]) {
		case "(Allow incoming connections)":
			state = "allowed"
		case "(Block incoming connections)":
			state = "blocked"
		default:
			return nil, errors.New("unrecognized firewall application state")
		}
		path = strings.TrimSpace(path)
		if _, tracked := result[path]; tracked {
			result[path] = state
		}
		seen++
	}
	if seen != want {
		return nil, errors.New("firewall inventory count differs")
	}
	return result, nil
}

func (d *Deployer) setFirewall(path, state string) error {
	if state != "allowed" && state != "blocked" && state != "absent" {
		return errors.New("invalid firewall target state")
	}
	if state == "absent" {
		if _, err := d.Run(firewallTool, "--remove", path); err != nil {
			return err
		}
	} else {
		if _, err := d.Run(firewallTool, "--add", path); err != nil {
			return err
		}
		option := "--unblockapp"
		if state == "blocked" {
			option = "--blockapp"
		}
		if _, err := d.Run(firewallTool, option, path); err != nil {
			return err
		}
	}
	current, err := d.firewallStates([]string{path})
	if err != nil {
		return err
	}
	if current[path] != state {
		return fmt.Errorf("firewall change did not take effect: %s", path)
	}
	return nil
}
