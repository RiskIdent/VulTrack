package autoassess

import (
	"strings"
	"testing"
)

func TestHeaderOrDocKind(t *testing.T) {
	dismissed := map[string]string{
		"linux-libc-dev":                  "kernel headers for user space",
		"linux-headers-6.8.0-124":         "kernel headers",
		"linux-headers-6.8.0-124-generic": "kernel headers",
		"linux-headers-generic":           "kernel headers",
		"linux-hwe-6.8-headers-6.8.0-124": "kernel headers",
		"linux-aws-headers-6.8.0-1015":    "kernel headers",
		"linux-oem-6.8-headers":           "kernel headers",
		"linux-source-6.8.0":              "kernel sources",
		"linux-source":                    "kernel sources",
		"linux-doc":                       "documentation",
		"python3-doc":                     "documentation",
		"openssl-doc":                     "documentation",
	}
	for pkg, want := range dismissed {
		if got := headerOrDocKind(pkg); got != want {
			t.Errorf("%s: got %q, want %q", pkg, got, want)
		}
	}
	kept := []string{
		"linux-image-6.8.0-124-generic", "linux-modules-6.8.0-124-generic", "linux-tools-common",
		"linux-firmware", "kernel", "libssl-dev", "libssl3t64", "openssh-server", "-doc", "doc",
		"linux-headers", // not a real package; without a suffix it is ambiguous
		"docker.io", "libdocument1",
	}
	for _, pkg := range kept {
		if got := headerOrDocKind(pkg); got != "" {
			t.Errorf("%s must not be dismissed, got %q", pkg, got)
		}
	}
}

func f(cve, pkg string) Finding { return Finding{CVEID: cve, Package: pkg, PackageVersion: "1.0"} }

func TestDecide(t *testing.T) {
	epssHigh, epssLow := 0.5, 0.01
	findings := []Finding{
		f("CVE-1", "linux-libc-dev"),                        // headers only
		f("CVE-2", "linux-libc-dev"), f("CVE-2", "libfoo1"), // one package still affected
		{CVEID: "CVE-3", Package: "bar", VexStatus: "not_affected", VexJustification: "code not present"},
		{CVEID: "CVE-3", Package: "bar-doc"}, // mixed rules
		f("CVE-4", "linux-headers-6.8.0-1"),  // KEV
		f("CVE-5", "python3-doc"),            // high EPSS
		f("CVE-6", "python3-doc"),            // low EPSS
		f("CVE-7", "python3-doc"),            // verified exploit
	}
	signals := map[string]CVESignals{
		"CVE-4": {InKEV: true},
		"CVE-5": {EPSS: &epssHigh},
		"CVE-6": {EPSS: &epssLow},
		"CVE-7": {VerifiedExploit: true},
	}
	got := Decide(findings, Rules, signals, GuardConfig{Exploit: true, EPSS: 0.1})

	if _, ok := got["CVE-2"]; ok {
		t.Error("CVE-2 has an undismissed finding and must stay open")
	}
	if d := got["CVE-1"]; len(d.RuleIDs) != 1 || d.RuleIDs[0] != "R-HDR" || len(d.Guards) != 0 {
		t.Errorf("CVE-1 = %+v", d)
	}
	d3 := got["CVE-3"]
	if strings.Join(d3.RuleIDs, ",") != "R-HDR,R-VEX" || len(d3.Evidence.Packages) != 2 {
		t.Errorf("CVE-3 = %+v", d3)
	}
	if d3.Evidence.Packages[0].Package != "bar" || d3.Evidence.Packages[0].Rule != "R-VEX" ||
		!strings.Contains(d3.Evidence.Packages[0].Detail, "code not present") {
		t.Errorf("CVE-3 evidence = %+v", d3.Evidence.Packages)
	}
	for cve, guard := range map[string]string{"CVE-4": "G-KEV", "CVE-5": "G-EPSS", "CVE-7": "G-EXPLOIT"} {
		if g := got[cve].Guards; len(g) != 1 || g[0] != guard {
			t.Errorf("%s guards = %v, want %s", cve, g, guard)
		}
		if !strings.Contains(got[cve].Reason, "blocked by "+guard) {
			t.Errorf("%s reason = %q", cve, got[cve].Reason)
		}
	}
	if len(got["CVE-6"].Guards) != 0 {
		t.Errorf("CVE-6 below the EPSS threshold: guards = %v", got["CVE-6"].Guards)
	}

	t.Run("optional guards off; KEV stays on", func(t *testing.T) {
		off := Decide(findings, Rules, signals, GuardConfig{})
		if len(off["CVE-5"].Guards) != 0 || len(off["CVE-7"].Guards) != 0 {
			t.Errorf("EPSS/exploit guards should be off: %v %v", off["CVE-5"].Guards, off["CVE-7"].Guards)
		}
		if len(off["CVE-4"].Guards) != 1 {
			t.Error("G-KEV must always apply")
		}
	})

	t.Run("a disabled rule decides nothing", func(t *testing.T) {
		onlyVEX := Decide(findings, []Rule{vexNotAffected{}}, signals, GuardConfig{})
		if len(onlyVEX) != 0 {
			t.Errorf("without R-HDR, no CVE is fully dismissed: %v", onlyVEX)
		}
	})

	t.Run("evidence is deterministic", func(t *testing.T) {
		shuffled := append([]Finding{}, findings...)
		for i, j := 0, len(shuffled)-1; i < j; i, j = i+1, j-1 {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		}
		again := Decide(shuffled, Rules, signals, GuardConfig{Exploit: true, EPSS: 0.1})
		for cve, d := range got {
			if string(again[cve].EvidenceJSON()) != string(d.EvidenceJSON()) || again[cve].Reason != d.Reason {
				t.Errorf("%s differs with another finding order", cve)
			}
		}
	})
}
