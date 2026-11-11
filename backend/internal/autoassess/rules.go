// Package autoassess decides automatically, with deterministic rules, which
// findings are not relevant on a server. It never decides "relevant": anything a
// rule cannot dismiss stays open for a human. See docs/AUTO_ASSESSMENT_PLAN.md.
package autoassess

import (
	"fmt"
	"strings"
)

// Finding is the part of an active finding the rules look at.
type Finding struct {
	CVEID            string
	Package          string
	PackageVersion   string
	FixState         string
	VexStatus        string
	VexJustification string
}

// Rule dismisses individual findings. A (server, CVE) pair is decided only when
// every one of its active findings is dismissed by some rule.
//
// Changing what a rule decides means bumping Version: the version is part of
// every stored decision, so all its decisions are re-evaluated and the audit
// trail shows which version decided.
type Rule interface {
	ID() string
	Version() int
	Description() string
	// Dismiss reports whether the finding is not relevant on the host, with a
	// one-line explanation that is stored as evidence. When it does not
	// dismiss, the explanation may say why (shown when a decision is revoked);
	// "" means the rule does not apply to the finding. h may be nil or partly
	// unknown.
	Dismiss(f Finding, h *Host) (bool, string)
}

// FactReader is implemented by rules that read runtime facts. The snapshot
// hashes of those categories are recorded with the decision, and new
// decisions wait until the facts have settled.
type FactReader interface {
	FactCategories() []string
}

// Rules is the rule catalogue in evaluation order. The first rule that
// dismisses a finding is recorded for it.
var Rules = []Rule{vexNotAffected{}, headersAndDocs{}, kernelModules{}, unusedPackage{}, aiPreconditions{}}

// RuleByID returns the rule with the given ID, or nil.
func RuleByID(id string) Rule {
	for _, r := range Rules {
		if r.ID() == id {
			return r
		}
	}
	return nil
}

// R-VEX: Canonical's VEX data states the package is not affected.
type vexNotAffected struct{}

func (vexNotAffected) ID() string   { return "R-VEX" }
func (vexNotAffected) Version() int { return 1 }
func (vexNotAffected) Description() string {
	return "Canonical's VEX data states that the package is not affected by the CVE."
}
func (vexNotAffected) Dismiss(f Finding, _ *Host) (bool, string) {
	if f.VexStatus != "not_affected" {
		if f.VexStatus == "" {
			return false, "no Canonical VEX statement"
		}
		return false, "Canonical VEX status is " + f.VexStatus
	}
	if f.VexJustification != "" {
		return true, "Canonical VEX: not affected (" + f.VexJustification + ")"
	}
	return true, "Canonical VEX: not affected"
}

// R-HDR: the package ships only kernel headers, sources or documentation, which
// no running code is built from on the server itself.
type headersAndDocs struct{}

func (headersAndDocs) ID() string   { return "R-HDR" }
func (headersAndDocs) Version() int { return 1 }
func (headersAndDocs) Description() string {
	return "The package ships only kernel headers, kernel sources or documentation (linux-libc-dev, linux-headers-*, linux-*-headers-*, linux-source-*, linux-doc, *-doc); no code from it runs on the server."
}
func (headersAndDocs) Dismiss(f Finding, _ *Host) (bool, string) {
	if kind := headerOrDocKind(f.Package); kind != "" {
		return true, fmt.Sprintf("Package %s contains only %s", f.Package, kind)
	}
	return false, ""
}

// headerOrDocKind classifies package names that contain no executable code, or
// returns "". The list is deliberately narrow: development packages (-dev) are
// not included, because static libraries in them end up in programs built on
// the host.
func headerOrDocKind(pkg string) string {
	switch {
	case pkg == "linux-libc-dev":
		return "kernel headers for user space"
	case strings.HasPrefix(pkg, "linux-"):
		rest := strings.TrimPrefix(pkg, "linux-")
		switch {
		case strings.HasPrefix(rest, "headers-") || strings.Contains(rest, "-headers-") || strings.HasSuffix(rest, "-headers"):
			return "kernel headers"
		case strings.HasPrefix(rest, "source-") || rest == "source":
			return "kernel sources"
		case rest == "doc" || strings.HasSuffix(rest, "-doc"):
			return "documentation"
		}
	case strings.HasSuffix(pkg, "-doc") && len(pkg) > len("-doc"):
		return "documentation"
	}
	return ""
}

// CVESignals are the per-CVE facts the guards look at.
type CVESignals struct {
	InKEV           bool
	EPSS            *float64
	VerifiedExploit bool
}

// GuardConfig selects the optional guards. G-KEV is always on.
type GuardConfig struct {
	Exploit bool
	EPSS    float64 // 0 = off
}

// Guard is a guard that blocks a dismissal, with a stable explanation (stable,
// so a daily EPSS change does not rewrite an unchanged decision).
type Guard struct {
	ID     string `json:"id"`
	Detail string `json:"detail"`
}

// Guards returns the guards that block an automated dismissal of the CVE, in a
// fixed order.
func Guards(sig CVESignals, cfg GuardConfig) []Guard {
	var g []Guard
	if sig.InKEV {
		g = append(g, Guard{"G-KEV", "listed in the CISA Known Exploited Vulnerabilities catalog"})
	}
	if cfg.Exploit && sig.VerifiedExploit {
		g = append(g, Guard{"G-EXPLOIT", "verified public exploit in ExploitDB"})
	}
	if cfg.EPSS > 0 && sig.EPSS != nil && *sig.EPSS >= cfg.EPSS {
		g = append(g, Guard{"G-EPSS", fmt.Sprintf("EPSS at or above %g%%", cfg.EPSS*100)})
	}
	return g
}

// GuardDescriptions documents the guards for the UI.
var GuardDescriptions = map[string]string{
	"G-KEV":     "The CVE is listed in the CISA Known Exploited Vulnerabilities catalog. Always on.",
	"G-EXPLOIT": "A verified public exploit for the CVE is listed in ExploitDB.",
	"G-EPSS":    "The CVE's EPSS score is at or above the configured threshold.",
}
