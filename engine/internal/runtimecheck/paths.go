// Package runtimecheck provides read-only runtime checks shared by maintenance
// and deployment. It contains no installation or service-replacement actions.
package runtimecheck

// Paths are the installed locations the deployment manages.
type Paths struct {
	NativeDNS                                                                    bool
	ServiceConfig, SupervisorPlist                                               string
	HealthLog                                                                    string
	State, Plist, Config, Binary, Tool, Rules, Cache, LogDir, Lock, BackupParent string
	HealthLock                                                                   string
}

var Production = Paths{
	State:        "/var/db/network-domain-proxy.previous.json",
	Plist:        "/Library/LaunchDaemons/com.local.network-domain-proxy.plist",
	Config:       "/usr/local/etc/network-domain-proxy.json",
	Binary:       "/usr/local/libexec/network-domain-engine",
	Tool:         "/usr/local/sbin/network-domain-proxy-deploy",
	Rules:        "/usr/local/etc/network-domain-rules-independent",
	Cache:        "/var/db/network-domain-proxy/independent-cache",
	LogDir:       "/var/log/network-domain-proxy",
	Lock:         "/var/db/network-domain-proxy.deploy.lock",
	BackupParent: "/var/db",
	HealthLock:   "/var/run/network-split-domestic-health.flock",
	HealthLog:    "/var/log/network-split-domestic-health.log",
}

const (
	ProxyLabel         = "system/com.local.network-domain-proxy"
	HealthPlistName    = "com.local.network-split-domestic-health.plist"
	LegacyHealthScript = "network-split-domestic-health.sh"
	HealthBinaryName   = "network-split-health"
	ServiceLabel       = "com.local.network-split-service"
	ServiceConfigPath  = "/usr/local/etc/network-split-service.json"
	JobsDirectory      = "/usr/local/etc/network-split-jobs"
	NativeDNSLabel     = "com.local.network-split-dns"
)

// Unified uses one executable; worker plists are registered by the parent job,
// not discovered independently in LaunchDaemons at boot.
func Unified() Paths {
	p := Production
	p.Tool = p.Binary
	p.Plist = JobsDirectory + "/com.local.network-domain-proxy.plist"
	p.ServiceConfig = ServiceConfigPath
	p.SupervisorPlist = "/Library/LaunchDaemons/" + ServiceLabel + ".plist"
	return p
}
