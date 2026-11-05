package autoassess

import (
	"strings"
	"testing"
	"time"
)

const day = 24 * time.Hour

// unusedHost: curl → libcurl4t64 → libssl3t64; libold1 is an orphan; libplug
// is an orphan plugin; meta (no entry points) depends on libmeta.
func unusedHost() *Host {
	p := NewPackageHost([]PackageInfo{
		{Package: "curl", EntryPoints: []string{"executable"}, Depends: []string{"libcurl4t64"}},
		{Package: "libcurl4t64", Depends: []string{"libssl3t64"}},
		{Package: "libssl3t64", EntryPoints: []string{"plugin"}},
		{Package: "libold1", Depends: []string{"libc6"}},
		{Package: "libplug", EntryPoints: []string{"plugin"}},
		{Package: "meta", Depends: []string{"libmeta"}},
		{Package: "libmeta"},
		{Package: "libc6"},
	})
	p.ObservedFor, p.Window = 20*day, 14*day
	p.LastInUse = map[string]time.Duration{"libc6": time.Hour}
	return &Host{Packages: p, FactHashes: map[string]string{"packageInfo": "pi1"}}
}

func TestUnusedReachability(t *testing.T) {
	p := unusedHost().Packages
	for pkg, want := range map[string]bool{"libcurl4t64": true, "libssl3t64": true, "libold1": false, "libc6": false, "libmeta": false} {
		if p.Reachable[pkg] != want {
			t.Errorf("%s reachable = %v, want %v", pkg, p.Reachable[pkg], want)
		}
	}
	// cycles terminate
	c := NewPackageHost([]PackageInfo{{Package: "a", EntryPoints: []string{"executable"}, Depends: []string{"b"}}, {Package: "b", Depends: []string{"a"}}})
	if !c.Reachable["b"] {
		t.Error("b is reachable")
	}
}

func TestUnusedDismisses(t *testing.T) {
	for _, pkg := range []string{"libold1", "libmeta"} {
		ok, d := unusedPackage{}.Dismiss(Finding{CVEID: "CVE-1", Package: pkg}, unusedHost())
		if !ok || !strings.Contains(d, "not in use for 14 days") {
			t.Errorf("%s: %v %q", pkg, ok, d)
		}
	}
	// seen in use, but before the window
	h := unusedHost()
	h.Packages.LastInUse["libold1"] = 15 * day
	if ok, _ := (unusedPackage{}).Dismiss(Finding{Package: "libold1"}, h); !ok {
		t.Error("in use before the window only")
	}
}

func TestUnusedKeepsOpen(t *testing.T) {
	cases := map[string]struct {
		pkg    string
		mutate func(h *Host)
	}{
		"no package info":           {"libold1", func(h *Host) { h.Packages = nil }},
		"observation too short":     {"libold1", func(h *Host) { h.Packages.ObservedFor = 13 * day }},
		"not observed":              {"libold1", func(h *Host) { h.Packages.ObservedFor = 0 }},
		"in use within the window":  {"libold1", func(h *Host) { h.Packages.LastInUse["libold1"] = 13 * day }},
		"not listed in packageInfo": {"libunknown", func(*Host) {}},
		"own entry points":          {"libplug", func(*Host) {}},
		"needed by curl":            {"libcurl4t64", func(*Host) {}},
		"needed transitively":       {"libssl3t64", func(*Host) {}},
		"in use (libc6)":            {"libc6", func(*Host) {}},
		"kernel pseudo-package":     {"kernel", func(*Host) {}},
		"window not configured":     {"libold1", func(h *Host) { h.Packages.Window = 0 }},
	}
	for name, c := range cases {
		h := unusedHost()
		c.mutate(h)
		if ok, d := (unusedPackage{}).Dismiss(Finding{CVEID: "CVE-1", Package: c.pkg}, h); ok {
			t.Errorf("%s: dismissed (%s)", name, d)
		}
	}
}

func TestUnusedEvidence(t *testing.T) {
	ds := Decide([]Finding{{CVEID: "CVE-1", Package: "libold1"}}, unusedHost(), Rules, nil, GuardConfig{})
	d, ok := ds["CVE-1"]
	if !ok || d.RuleIDs[0] != "R-UNUSED" || d.Evidence.Facts["packageInfo"] != "pi1" {
		t.Fatalf("decision %+v", ds)
	}
	// a second finding of the same CVE in a used package keeps it open
	ds = Decide([]Finding{{CVEID: "CVE-1", Package: "libold1"}, {CVEID: "CVE-1", Package: "libcurl4t64"}}, unusedHost(), Rules, nil, GuardConfig{})
	if _, ok := ds["CVE-1"]; ok {
		t.Error("all findings of the CVE must be dismissed")
	}
}
