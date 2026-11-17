package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// Facts is the part of an assessment's input that can change the
// recommendation, coarsened where the raw value moves without meaning
// (EPSS changes daily, server counts with every scan, package versions with
// every update). An assessment is refreshed when its stored facts differ from
// the current ones.
type Facts map[string]string

// FactsOf extracts the facts of an assessment input.
func FactsOf(in AssessmentInput) Facts {
	cwes := slices.Clone(in.CWEIDs)
	slices.Sort(cwes)
	desc := sha256.Sum256([]byte(strings.TrimSpace(in.Description)))
	return Facts{
		"severity":       strings.ToLower(in.Severity),
		"cvss":           fmt.Sprintf("%.1f", in.CVSS3Score),
		"cvss_vector":    in.CVSS3Vector,
		"cwe":            strings.Join(cwes, ","),
		"package":        in.PackageName,
		"fix_available":  yesNo(in.FixAvailable),
		"exploit":        yesNo(in.ExploitAvailable),
		"vex":            in.VexStatus,
		"kev":            yesNo(in.InKEV),
		"kev_ransomware": yesNo(in.KEVRansomware),
		"epss":           epssBand(in.EPSS),
		"servers":        serverBand(in.AffectedServers),
		"description":    hex.EncodeToString(desc[:8]),
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func epssBand(p float64) string {
	switch {
	case p <= 0:
		return "unknown"
	case p < 0.01:
		return "<1%"
	case p < 0.10:
		return "1-10%"
	case p < 0.50:
		return "10-50%"
	}
	return ">=50%"
}

func serverBand(n int) string {
	switch {
	case n <= 1:
		return "1"
	case n < 10:
		return "2-9"
	case n < 50:
		return "10-49"
	}
	return ">=50"
}

// factLabels names the facts in change descriptions, in display order.
var factLabels = []struct{ key, label string }{
	{"kev", "CISA KEV"}, {"kev_ransomware", "KEV ransomware use"}, {"exploit", "public exploit"},
	{"fix_available", "fix available"}, {"vex", "VEX status"}, {"epss", "EPSS"},
	{"severity", "severity"}, {"cvss", "CVSS score"}, {"cvss_vector", "CVSS vector"}, {"cwe", "CWE"},
	{"servers", "affected servers"}, {"package", "package"}, {"description", "description"},
}

// Changes describes how the facts changed from old to f, e.g.
// "fix available: no → yes". Facts missing from old (an assessment made before
// a fact was collected) count as unchanged, except that no stored facts at all
// is reported as such.
func (f Facts) Changes(old Facts) []string {
	if len(old) == 0 {
		return []string{"assessed before KEV/EPSS data was included"}
	}
	var out []string
	for _, l := range factLabels {
		was, ok := old[l.key]
		if !ok || was == f[l.key] {
			continue
		}
		if l.key == "description" {
			out = append(out, "description updated")
			continue
		}
		out = append(out, fmt.Sprintf("%s: %s → %s", l.label, orNone(was), orNone(f[l.key])))
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
