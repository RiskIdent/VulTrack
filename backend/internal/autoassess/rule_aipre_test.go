package autoassess

import (
	"strings"
	"testing"

	"github.com/vultrack/vultrack/internal/ai"
)

func cond(t, pkg, scope string) ai.Condition {
	return ai.Condition{Type: t, Package: pkg, Scope: scope, Necessary: true, Confidence: "high"}
}

// aipreHost: nginx listens on 0.0.0.0:443, openssh-server only on 127.0.0.1,
// containers listen without package, a node exporter from /opt; userns on,
// unprivileged BPF off.
func aipreHost(paths ...ai.AttackPath) *Host {
	return &Host{
		Runtime: &RuntimeHost{
			ListenersKnown: true,
			Listeners: []Listener{
				{Address: "0.0.0.0", Port: 443, Process: "nginx", Exe: "/usr/sbin/nginx", Package: "nginx-core", HostNetns: true},
				{Address: "127.0.0.1", Port: 22, Process: "sshd", Exe: "/usr/sbin/sshd", Package: "openssh-server", HostNetns: true},
				{Address: "::", Port: 80, Process: "caddy", Exe: "/usr/bin/caddy", Unit: "docker-4d88.scope", HostNetns: true},
				{Address: "::", Port: 9100, Process: "node_exporter", Exe: "/opt/node_exporter/node_exporter", Unit: "node_exporter.service", HostNetns: true},
			},
			ServicesKnown: true,
			Services: []Service{
				{Unit: "nginx.service", ActiveState: "active", UnitFileState: "enabled", Package: "nginx"},
				{Unit: "cups.service", ActiveState: "inactive", UnitFileState: "masked", Package: "cups-daemon"},
				{Unit: "NetworkManager.service", ActiveState: "inactive"}, // not installed
			},
			Sysctls: map[string]string{"kernel.unprivileged_userns_clone": "1", "kernel.unprivileged_bpf_disabled": "2"},
		},
		Preconditions: map[string]PreconditionAnalysis{
			"CVE-1": {Model: "claude-sonnet-5-5", Short: "abcd1234", Result: ai.PreconditionResult{Determinable: true, Paths: paths}},
		},
	}
}

func dismiss(h *Host) (bool, string) {
	return aiPreconditions{}.Dismiss(Finding{CVEID: "CVE-1", Package: "libfoo"}, h)
}

func TestAIPreDismisses(t *testing.T) {
	cases := map[string][]ai.AttackPath{
		"no listener of the package": {{Requires: []ai.Condition{cond(ai.CondNetworkListener, "apache2", "any")}}},
		"sshd only on loopback":      {{Requires: []ai.Condition{cond(ai.CondNetworkListener, "openssh-server", "non_loopback")}}},
		"no service unit":            {{Requires: []ai.Condition{{Type: ai.CondServiceActive, Package: "apache2", Necessary: true, Confidence: "high"}}}},
		"service masked":             {{Requires: []ai.Condition{{Type: ai.CondServiceActive, Package: "cups-daemon", Necessary: true, Confidence: "high"}}}},
		"unprivileged bpf off":       {{Requires: []ai.Condition{cond(ai.CondLocalUser, "", ""), cond(ai.CondUnprivilegedBPF, "", "")}}},
		"two paths, each blocked":    {{Requires: []ai.Condition{cond(ai.CondNetworkListener, "apache2", "any")}}, {Requires: []ai.Condition{cond(ai.CondUnprivilegedBPF, "", "")}}},
	}
	for name, paths := range cases {
		ok, d := dismiss(aipreHost(paths...))
		if !ok || !strings.Contains(d, "claude-sonnet-5-5 analysis abcd1234") {
			t.Errorf("%s: %v %q", name, ok, d)
		}
	}
}

func TestAIPreKeepsOpen(t *testing.T) {
	sshNonLoop := []ai.AttackPath{{Requires: []ai.Condition{cond(ai.CondNetworkListener, "openssh-server", "non_loopback")}}}
	cases := map[string]struct {
		paths  []ai.AttackPath
		mutate func(h *Host)
	}{
		"package listens":   {[]ai.AttackPath{{Requires: []ai.Condition{cond(ai.CondNetworkListener, "nginx-core", "non_loopback")}}}, nil},
		"loopback suffices": {[]ai.AttackPath{{Requires: []ai.Condition{cond(ai.CondNetworkListener, "openssh-server", "any")}}}, nil},
		"socket activation by systemd": {sshNonLoop, func(h *Host) {
			h.Runtime.Listeners = append(h.Runtime.Listeners, Listener{Address: "0.0.0.0", Port: 22, Process: "systemd", Package: "systemd", HostNetns: true})
		}},
		"listener of unknown owner in a system path": {sshNonLoop, func(h *Host) {
			h.Runtime.Listeners = append(h.Runtime.Listeners, Listener{Address: "0.0.0.0", Port: 2222, Process: "x", Exe: "/usr/sbin/x", HostNetns: true})
		}},
		"listener without exe": {sshNonLoop, func(h *Host) {
			h.Runtime.Listeners = append(h.Runtime.Listeners, Listener{Address: "0.0.0.0", Port: 2222, HostNetns: true})
		}},
		"listeners unknown": {sshNonLoop, func(h *Host) { h.Runtime.ListenersKnown = false }},
		"no runtime facts":  {sshNonLoop, func(h *Host) { h.Runtime = nil }},
		"no analysis":       {sshNonLoop, func(h *Host) { h.Preconditions = nil }},
		"not determinable": {sshNonLoop, func(h *Host) {
			a := h.Preconditions["CVE-1"]
			a.Result.Determinable = false
			h.Preconditions["CVE-1"] = a
		}},
		"no paths":          {nil, nil},
		"medium confidence": {[]ai.AttackPath{{Requires: []ai.Condition{{Type: ai.CondNetworkListener, Package: "apache2", Scope: "any", Necessary: true, Confidence: "medium"}}}}, nil},
		"not necessary":     {[]ai.AttackPath{{Requires: []ai.Condition{{Type: ai.CondNetworkListener, Package: "apache2", Scope: "any", Confidence: "high"}}}}, nil},
		"second path open":  {[]ai.AttackPath{{Requires: []ai.Condition{cond(ai.CondNetworkListener, "apache2", "any")}}, {Requires: []ai.Condition{cond(ai.CondLocalUser, "", "")}}}, nil},
		"service running":   {[]ai.AttackPath{{Requires: []ai.Condition{{Type: ai.CondServiceActive, Package: "nginx", Necessary: true, Confidence: "high"}}}}, nil},
		"unit of unknown origin installed": {[]ai.AttackPath{{Requires: []ai.Condition{{Type: ai.CondServiceActive, Package: "apache2", Necessary: true, Confidence: "high"}}}}, func(h *Host) {
			h.Runtime.Services = append(h.Runtime.Services, Service{Unit: "custom.service", UnitFileState: "enabled"})
		}},
		"userns allowed":                       {[]ai.AttackPath{{Requires: []ai.Condition{cond(ai.CondUnprivilegedUserns, "", "")}}}, nil},
		"sysctls unknown":                      {[]ai.AttackPath{{Requires: []ai.Condition{cond(ai.CondUnprivilegedBPF, "", "")}}}, func(h *Host) { h.Runtime.Sysctls = nil }},
		"package_in_use without package facts": {[]ai.AttackPath{{Requires: []ai.Condition{cond(ai.CondPackageInUse, "libfoo", "")}}}, nil},
		"any listening program":                {[]ai.AttackPath{{Requires: []ai.Condition{cond(ai.CondNetworkListener, "", "non_loopback")}}}, nil},
		"any service":                          {[]ai.AttackPath{{Requires: []ai.Condition{{Type: ai.CondServiceActive, Necessary: true, Confidence: "high"}}}}, nil},
		"any package in use":                   {[]ai.AttackPath{{Requires: []ai.Condition{cond(ai.CondPackageInUse, "", "")}}}, func(h *Host) { h.Packages = unusedHost().Packages }},
		"never checkable":                      {[]ai.AttackPath{{Requires: []ai.Condition{cond(ai.CondKernelCode, "", ""), cond(ai.CondConfigDependent, "", ""), cond(ai.CondPhysicalAccess, "", "")}}}, nil},
	}
	for name, c := range cases {
		h := aipreHost(c.paths...)
		if c.mutate != nil {
			c.mutate(h)
		}
		if ok, d := dismiss(h); ok {
			t.Errorf("%s: dismissed (%s)", name, d)
		}
	}
}

func TestAIPrePackageInUse(t *testing.T) {
	h := aipreHost(ai.AttackPath{Requires: []ai.Condition{cond(ai.CondPackageInUse, "libold1", "")}})
	h.Packages = unusedHost().Packages
	if ok, d := dismiss(h); !ok || !strings.Contains(d, "libold1: no entry points") {
		t.Errorf("unused package: %v %q", ok, d)
	}
	h = aipreHost(ai.AttackPath{Requires: []ai.Condition{cond(ai.CondPackageInUse, "libcurl4t64", "")}})
	h.Packages = unusedHost().Packages
	if ok, _ := dismiss(h); ok {
		t.Error("a library needed by curl may be in use")
	}
}
