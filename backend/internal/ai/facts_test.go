package ai

import (
	"reflect"
	"strings"
	"testing"
)

func TestFactsChanges(t *testing.T) {
	in := AssessmentInput{CVEID: "CVE-1", Severity: "High", CVSS3Score: 7.5, PackageName: "openssl",
		PackageVersion: "3.0.2-1", EPSS: 0.004, AffectedServers: 3, Description: "overflow"}
	old := FactsOf(in)

	// Noise does not count: another version, EPSS and server count within their bands.
	noise := in
	noise.PackageVersion, noise.EPSS, noise.AffectedServers = "3.0.2-2", 0.008, 7
	if c := FactsOf(noise).Changes(old); len(c) != 0 {
		t.Errorf("noise reported as changes: %v", c)
	}

	changed := in
	changed.FixAvailable, changed.InKEV, changed.EPSS = true, true, 0.2
	want := []string{"CISA KEV: no → yes", "fix available: no → yes", "EPSS: <1% → 10-50%"}
	if c := FactsOf(changed).Changes(old); !reflect.DeepEqual(c, want) {
		t.Errorf("changes %v, want %v", c, want)
	}

	if c := FactsOf(in).Changes(nil); len(c) != 1 || !strings.Contains(c[0], "KEV/EPSS") {
		t.Errorf("legacy assessment: %v", c)
	}
	// A fact added later is not a change for assessments that lack it.
	delete(old, "epss")
	if c := FactsOf(changed).Changes(old); hasPrefix(c, "EPSS") {
		t.Errorf("missing old fact reported: %v", c)
	}

	msg := buildUserMessage(changed)
	if !strings.Contains(msg, "Known Exploited Vulnerabilities (actively exploited in the wild): yes") ||
		!strings.Contains(msg, "EPSS (probability of exploitation in the next 30 days): 20.00%") {
		t.Errorf("user message lacks KEV/EPSS:\n%s", msg)
	}
}

func hasPrefix(list []string, prefix string) bool {
	for _, s := range list {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}
