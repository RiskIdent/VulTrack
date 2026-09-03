package scanner

import "testing"

func TestKernelEVR(t *testing.T) {
	tests := []struct {
		release string
		want    string
	}{
		{"6.8.0-79-generic", "0:6.8.0-79"},
		{"6.8.0-79-generic-64k", "0:6.8.0-79"},
		{"6.8.0-1029-aws", "0:6.8.0-1029"},
		{"6.14.0-33-generic", "0:6.14.0-33"},
		{"6.8.0-1017-oem", "0:6.8.0-1017"},
		{"6.8.1-1004-realtime", "0:6.8.1-1004"},
		{"  6.8.0-79-generic  ", "0:6.8.0-79"},
		// No flavour suffix: Canonical's own regex requires one, so there is
		// nothing to derive and callers must not compare a guess.
		{"6.8.0-79", ""},
		{"", ""},
		{"not-a-kernel", ""},
	}

	for _, tc := range tests {
		if got := KernelEVR(tc.release); got != tc.want {
			t.Errorf("KernelEVR(%q) = %q, want %q", tc.release, got, tc.want)
		}
	}
}

// TestKernelEVRComparison guards the reason KernelEVR exists: comparing the raw
// `uname -r` string against a kernel package version puts the flavour into the
// Debian revision field and inverts the verdict.
func TestKernelEVRComparison(t *testing.T) {
	const release = "6.8.0-79-generic"
	evr := KernelEVR(release)

	// Fixed in a higher revision of the same ABI: the running kernel is older.
	if !EvaluateVersionOperation(evr, "6.8.0-79.79", "less than", "dpkg") {
		t.Errorf("expected %q to be less than 6.8.0-79.79", evr)
	}
	if EvaluateVersionOperation(release, "6.8.0-79.79", "less than", "dpkg") {
		t.Error("raw uname release compared as up to date against 6.8.0-79.79; " +
			"the flavour suffix must not be used as a Debian revision")
	}

	// Already past the fix.
	if EvaluateVersionOperation(evr, "6.8.0-35.35", "less than", "dpkg") {
		t.Errorf("expected %q not to be less than 6.8.0-35.35", evr)
	}

	// A different flavour's much higher ABI must still compare as older; the
	// uname test is what keeps such a criterion from applying, not the version.
	if !EvaluateVersionOperation(evr, "6.8.0-1006.6", "less than", "dpkg") {
		t.Errorf("expected %q to be less than 6.8.0-1006.6", evr)
	}
}

func TestEvaluateVersionOperationDpkg(t *testing.T) {
	tests := []struct {
		installed string
		fixed     string
		operation string
		want      bool
	}{
		{"3.0.13-0ubuntu3.1", "3.0.13-0ubuntu3.2", "less than", true},
		{"3.0.13-0ubuntu3.2", "3.0.13-0ubuntu3.2", "less than", false},
		{"3.0.13-0ubuntu3.3", "3.0.13-0ubuntu3.2", "less than", false},
		{"3.0.13-0ubuntu3.2", "3.0.13-0ubuntu3.2", "less than or equal", true},
		{"1:2.0-1", "2.0-1", "greater than", true},
		{"1.0~rc1-1", "1.0-1", "less than", true},
		// An empty side means there is nothing to compare.
		{"", "1.0-1", "less than", false},
		{"1.0-1", "", "less than", false},
	}

	for _, tc := range tests {
		got := EvaluateVersionOperation(tc.installed, tc.fixed, tc.operation, "dpkg")
		if got != tc.want {
			t.Errorf("EvaluateVersionOperation(%q, %q, %q) = %v, want %v",
				tc.installed, tc.fixed, tc.operation, got, tc.want)
		}
	}
}
