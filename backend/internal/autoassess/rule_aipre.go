package autoassess

import (
	"fmt"
	"strings"

	"github.com/vultrack/vultrack/internal/ai"
)

// AI-PRE: the AI precondition analysis lists the attack paths of a CVE and
// their conditions; this rule checks them against the server's facts. A
// server is dismissed only if every path contains a condition that is
// necessary, has high confidence and is definitely false here. The model
// never decides about a server; the check is deterministic.
//
// Checkable conditions and when they count as false:
//   - network_listener(P, scope): listeners are known, none belongs to P (on a
//     non-loopback address for scope non_loopback), and no listener with an
//     unknown owner could be P: sockets held by systemd or an inetd
//     (socket activation) and host processes without owning package in
//     system paths count as unknown;
//   - package_in_use(P): as R-UNUSED (no entry points, not needed by a
//     package with entry points, not in use for the observation period);
//   - service_active(P or unit): services are known, no service unit belongs
//     to P (or has that name), unless all of them are masked; and no installed
//     service unit without known package exists that could run P;
//   - unprivileged_userns: kernel.unprivileged_userns_clone = 0 or
//     user.max_user_namespaces = 0;
//   - unprivileged_bpf: kernel.unprivileged_bpf_disabled = 1 or 2.
//
// kernel_code, local_user, physical_access, user_interaction and
// config_dependent are never false.
type aiPreconditions struct{}

func (aiPreconditions) ID() string   { return "AI-PRE" }
func (aiPreconditions) Version() int { return 1 }
func (aiPreconditions) Description() string {
	return "An AI model lists the attack paths of the CVE and their conditions; VulTrack checks them against the server's facts. " +
		"Dismissed only if every path has a necessary, high-confidence condition that is definitely false on the server " +
		"(no listener of the package, package unused, service not installed, unprivileged user namespaces or BPF disabled)."
}
func (aiPreconditions) FactCategories() []string {
	return []string{"listeners", "services", "kernel", "packageInfo"}
}

// conditionFacts is the fact category each checkable condition reads.
var conditionFacts = map[string]string{
	ai.CondNetworkListener:    "listeners",
	ai.CondPackageInUse:       "packageInfo",
	ai.CondServiceActive:      "services",
	ai.CondUnprivilegedUserns: "kernel",
	ai.CondUnprivilegedBPF:    "kernel",
}

// FactsUsedBy returns the categories of the conditions that block the paths
// of f's CVE: a decision rests on those only, so an unrelated change (a
// service starting, a module loading) neither delays nor changes it.
func (aiPreconditions) FactsUsedBy(f Finding, h *Host) []string {
	if h == nil || h.Runtime == nil {
		return nil
	}
	a, ok := h.Preconditions[f.CVEID]
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range a.Result.Paths {
		for _, c := range p.Requires {
			if !c.Necessary || c.Confidence != "high" {
				continue
			}
			if _, isFalse := h.conditionFalse(c); isFalse {
				if cat := conditionFacts[c.Type]; cat != "" && !seen[cat] {
					seen[cat] = true
					out = append(out, cat)
				}
				break
			}
		}
	}
	return out
}

func (aiPreconditions) Dismiss(f Finding, h *Host) (bool, string) {
	if h == nil || h.Preconditions == nil {
		return false, "no AI precondition analysis"
	}
	a, ok := h.Preconditions[f.CVEID]
	switch {
	case !ok:
		return false, "no AI precondition analysis"
	case h.Runtime == nil:
		return false, "no runtime facts from the agent"
	case !a.Result.Determinable:
		return false, "the analysis could not determine the preconditions"
	case len(a.Result.Paths) == 0:
		return false, "the analysis lists no attack path"
	}
	parts := make([]string, 0, len(a.Result.Paths))
	for i, p := range a.Result.Paths {
		reason := ""
		for _, c := range p.Requires {
			if !c.Necessary || c.Confidence != "high" {
				continue
			}
			if why, isFalse := h.conditionFalse(c); isFalse {
				reason = why
				break
			}
		}
		if reason == "" {
			return false, fmt.Sprintf("attack path %d is not ruled out on this server", i+1)
		}
		parts = append(parts, fmt.Sprintf("path %d: %s", i+1, reason))
	}
	return true, fmt.Sprintf("%s analysis %s: %s", a.Model, a.Short, strings.Join(parts, "; "))
}

// conditionFalse reports whether c is definitely false on the host.
func (h *Host) conditionFalse(c ai.Condition) (string, bool) {
	r := h.Runtime
	switch c.Type {
	case ai.CondNetworkListener:
		if !r.ListenersKnown || c.Package == "" {
			return "", false
		}
		nonLoopback := c.Scope == "non_loopback"
		for _, l := range r.Listeners {
			if nonLoopback && isLoopback(l.Address) {
				continue
			}
			if l.Package == c.Package || l.unknownOwner() {
				return "", false
			}
		}
		if nonLoopback {
			return "no process of " + c.Package + " listens on a non-loopback address", true
		}
		return "no process of " + c.Package + " listens", true
	case ai.CondPackageInUse:
		if c.Package == "" {
			return "", false
		}
		if ok, why := h.Packages.Unused(c.Package); ok {
			return c.Package + ": " + why, true
		}
	case ai.CondServiceActive:
		if !r.ServicesKnown || (c.Package == "" && c.Unit == "") {
			return "", false // "any service" can never be ruled out
		}
		matched, unmasked := 0, 0
		for _, s := range r.Services {
			if s.Package == "" && s.UnitFileState != "" {
				return "", false // an installed unit of unknown origin could run it
			}
			if (c.Package != "" && s.Package == c.Package) || (c.Unit != "" && s.Unit == c.Unit) {
				matched++
				if s.UnitFileState != "masked" {
					unmasked++
				}
			}
		}
		name := c.Package
		if c.Unit != "" {
			name = c.Unit
		}
		switch {
		case matched == 0:
			return "no service unit of " + name + " installed", true
		case unmasked == 0:
			return "all service units of " + name + " masked", true
		}
	case ai.CondUnprivilegedUserns:
		if r.Sysctls == nil {
			return "", false
		}
		if r.Sysctls["kernel.unprivileged_userns_clone"] == "0" {
			return "kernel.unprivileged_userns_clone = 0", true
		}
		if r.Sysctls["user.max_user_namespaces"] == "0" {
			return "user.max_user_namespaces = 0", true
		}
	case ai.CondUnprivilegedBPF:
		if r.Sysctls == nil {
			return "", false
		}
		if v := r.Sysctls["kernel.unprivileged_bpf_disabled"]; v == "1" || v == "2" {
			return "kernel.unprivileged_bpf_disabled = " + v, true
		}
	}
	return "", false
}

func isLoopback(addr string) bool {
	return strings.HasPrefix(addr, "127.") || addr == "::1" || strings.HasPrefix(addr, "::ffff:127.")
}

// socketHolders accept connections for other programs (socket activation).
var socketHolders = map[string]bool{"systemd": true, "openbsd-inetd": true, "inetutils-inetd": true, "xinetd": true}

// unknownOwner: the listening program could belong to any package.
func (l Listener) unknownOwner() bool {
	if socketHolders[l.Package] || l.Process == "systemd" {
		return true
	}
	if l.Package != "" {
		return false
	}
	if strings.HasSuffix(l.Unit, ".scope") && (strings.HasPrefix(l.Unit, "docker-") || strings.HasPrefix(l.Unit, "libpod-") ||
		strings.Contains(l.Unit, "containerd")) {
		return false // container software, not a host package
	}
	if l.Exe == "" {
		return true
	}
	for _, p := range []string{"/usr/local/", "/opt/", "/home/", "/srv/"} {
		if strings.HasPrefix(l.Exe, p) {
			return false // not installed by dpkg
		}
	}
	return true
}
