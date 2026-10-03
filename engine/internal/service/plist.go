package service

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

type Job struct {
	Label      string
	Definition map[string]any
	Directory  string
}

func (j Job) Path() string {
	dir := j.Directory
	if dir == "" {
		dir = JobsDirectory
	}
	return filepath.Join(dir, j.Label+".plist")
}
func (j Job) Program() string     { return j.Definition["ProgramArguments"].([]string)[0] }
func (j Job) Arguments() []string { return j.Definition["ProgramArguments"].([]string) }

func Jobs(c Config) []Job {
	worker := func(label, role, log string, interval int, keep any) Job {
		def := map[string]any{"Label": label, "ProgramArguments": []string{Binary, "worker", role, "-service-config", ConfigPath}, "RunAtLoad": true, "ExitTimeOut": 15,
			"StandardOutPath": log + ".out", "StandardErrorPath": log + ".err"}
		if interval > 0 {
			def["StartInterval"] = interval
		}
		if keep != nil {
			def["KeepAlive"] = keep
		}
		return Job{Label: label, Definition: def}
	}
	proxy := Job{Label: "com.local.network-domain-proxy", Definition: map[string]any{"Label": "com.local.network-domain-proxy", "UserName": "nobody", "RunAtLoad": true, "KeepAlive": true, "ThrottleInterval": 5, "ExitTimeOut": 10,
		"ProgramArguments": []string{Binary, "run", "--disable-color", "--log-file", "/var/log/network-domain-proxy/service.log", "--log-max-size", "2097152", "--log-max-backups", "3", "-c", c.EngineConfig}}}
	dns := Job{Label: "homebrew.mxcl.dnsmasq", Definition: map[string]any{"Label": "homebrew.mxcl.dnsmasq", "RunAtLoad": true, "KeepAlive": true,
		"ProgramArguments": []string{c.Routes.DNSBinary, "--keep-in-foreground", "-C", c.Routes.DNSConfig}}}
	status := Job{Label: "com.local.network-split-log-guard", Definition: map[string]any{"Label": "com.local.network-split-log-guard", "UserName": c.Status.User, "RunAtLoad": true, "StartInterval": 300, "ExitTimeOut": 15,
		"EnvironmentVariables": map[string]any{"HOME": c.Status.Home}, "StandardOutPath": "/var/log/network-split-status.out", "StandardErrorPath": "/var/log/network-split-status.err",
		"ProgramArguments": []string{Binary, "worker", "status", "-output", c.Status.Output, "-state", c.Status.State, "-log", c.Status.Log}}}
	return []Job{dns, proxy, worker("com.local.network-split-dns-event-route-agent", "observe", "/var/log/network-split-dns-event-route-agent", 0, true),
		worker("com.local.china-route", "routes", "/var/log/china-route", 0, map[string]any{"NetworkState": true}),
		worker("com.local.network-split-guard", "guard", "/var/log/network-split-guard", 30, map[string]any{"NetworkState": true}),
		worker("com.local.network-split-domestic-health", "health", "/var/log/network-split-domestic-health", 30, nil), status}
}

func MainDefinition() map[string]any {
	return map[string]any{"Label": Label, "ProgramArguments": []string{Binary, "service", "-c", ConfigPath}, "RunAtLoad": true, "KeepAlive": true, "ThrottleInterval": 10, "ExitTimeOut": ParentExitTimeout,
		"StandardOutPath": "/var/log/network-split-service.out", "StandardErrorPath": "/var/log/network-split-service.err"}
}

// Plist encodes only the value types used by our launchd definitions, with
// deterministic key order and XML escaping supplied by the standard library.
func Plist(definition map[string]any) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString(xml.Header + "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	enc := xml.NewEncoder(&out)
	enc.Indent("", "  ")
	root := xml.StartElement{Name: xml.Name{Local: "plist"}, Attr: []xml.Attr{{Name: xml.Name{Local: "version"}, Value: "1.0"}}}
	if err := enc.EncodeToken(root); err != nil {
		return nil, err
	}
	var value func(any) error
	value = func(v any) error {
		tag := ""
		switch v.(type) {
		case map[string]any:
			tag = "dict"
		case []string:
			tag = "array"
		case string:
			tag = "string"
		case int:
			tag = "integer"
		case bool:
			tag = fmt.Sprint(v)
		default:
			return fmt.Errorf("unsupported plist type %T", v)
		}
		start := xml.StartElement{Name: xml.Name{Local: tag}}
		if err := enc.EncodeToken(start); err != nil {
			return err
		}
		switch v := v.(type) {
		case map[string]any:
			var keys []string
			for key := range v {
				keys = append(keys, key)
			}
			slices.Sort(keys)
			for _, key := range keys {
				if err := enc.EncodeElement(key, xml.StartElement{Name: xml.Name{Local: "key"}}); err != nil {
					return err
				}
				if err := value(v[key]); err != nil {
					return err
				}
			}
		case []string:
			for _, s := range v {
				if err := value(s); err != nil {
					return err
				}
			}
		case string:
			if err := enc.EncodeToken(xml.CharData(v)); err != nil {
				return err
			}
		case int:
			if err := enc.EncodeToken(xml.CharData(fmt.Sprint(v))); err != nil {
				return err
			}
		}
		return enc.EncodeToken(start.End())
	}
	if err := value(definition); err != nil {
		return nil, err
	}
	if err := enc.EncodeToken(root.End()); err != nil {
		return nil, err
	}
	if err := enc.Flush(); err != nil {
		return nil, err
	}
	return append(out.Bytes(), '\n'), nil
}

type LaunchInfo struct {
	Program, Path, State, Exit string
	PID                        int
	Arguments                  []string
}

func ParseLaunch(raw string) LaunchInfo {
	var result LaunchInfo
	values := map[string]string{}
	arguments := false
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "arguments = {" {
			arguments = true
			continue
		}
		if arguments {
			if line == "}" {
				arguments = false
			} else {
				result.Arguments = append(result.Arguments, line)
			}
			continue
		}
		if key, value, ok := strings.Cut(line, " = "); ok {
			if _, exists := values[key]; !exists {
				values[key] = value
			}
		}
	}
	result.Program, result.Path, result.State, result.Exit = values["program"], values["path"], values["state"], values["last exit code"]
	fmt.Sscan(values["pid"], &result.PID)
	return result
}

func (j Job) Matches(info LaunchInfo) bool {
	return info.Program == j.Program() && info.Path == j.Path() && slices.Equal(info.Arguments, j.Arguments())
}
