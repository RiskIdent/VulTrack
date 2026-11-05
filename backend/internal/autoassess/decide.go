package autoassess

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// PackageEvidence records which rule dismissed one finding of a decision.
type PackageEvidence struct {
	Package     string `json:"package"`
	Version     string `json:"version,omitempty"`
	Rule        string `json:"rule"`
	RuleVersion int    `json:"ruleVersion"`
	Detail      string `json:"detail"`
}

// Evidence is stored with every decision.
type Evidence struct {
	Packages []PackageEvidence `json:"packages"`
	Guards   []Guard           `json:"guards,omitempty"`
	// Facts holds, per runtime fact category a rule read, the hash of the
	// fact snapshot the decision is based on (kept as long as it is referenced).
	Facts map[string]string `json:"facts,omitempty"`
}

// Decision is the automated verdict for one (server, CVE) pair.
type Decision struct {
	CVEID    string
	Verdict  string // always "not_relevant"
	RuleIDs  []string
	Guards   []string
	Reason   string
	Evidence Evidence
}

// EvidenceJSON is the canonical encoding of the evidence, used to store it and
// to tell whether a decision changed.
func (d Decision) EvidenceJSON() []byte {
	b, _ := json.Marshal(d.Evidence)
	return b
}

// Decide computes the decisions for one server's active findings on host h
// (nil when nothing is known about the host). enabled
// selects the rules to run (rules in mode off are left out). signals holds the
// guard inputs per CVE; a CVE missing from it has no KEV listing, EPSS score or
// exploit.
func Decide(findings []Finding, h *Host, enabled []Rule, signals map[string]CVESignals, guards GuardConfig) map[string]Decision {
	byCVE := map[string][]Finding{}
	for _, f := range findings {
		byCVE[f.CVEID] = append(byCVE[f.CVEID], f)
	}

	out := map[string]Decision{}
	for cve, fs := range byCVE {
		sort.Slice(fs, func(i, j int) bool { return fs[i].Package < fs[j].Package })
		var ev Evidence
		decided := true
		for _, f := range fs {
			hit := false
			for _, r := range enabled {
				if ok, detail := r.Dismiss(f, h); ok {
					ev.Packages = append(ev.Packages, PackageEvidence{
						Package: f.Package, Version: f.PackageVersion,
						Rule: r.ID(), RuleVersion: r.Version(), Detail: detail,
					})
					hit = true
					break
				}
			}
			if !hit {
				decided = false
				break
			}
		}
		if !decided || len(ev.Packages) == 0 {
			continue
		}

		ruleSet := map[string]bool{}
		for _, p := range ev.Packages {
			ruleSet[p.Rule] = true
			if fr, ok := RuleByID(p.Rule).(FactReader); ok && h != nil {
				for _, cat := range fr.FactCategories() {
					if hash := h.FactHashes[cat]; hash != "" {
						if ev.Facts == nil {
							ev.Facts = map[string]string{}
						}
						ev.Facts[cat] = hash
					}
				}
			}
		}
		ruleIDs := make([]string, 0, len(ruleSet))
		for id := range ruleSet {
			ruleIDs = append(ruleIDs, id)
		}
		sort.Strings(ruleIDs)

		ev.Guards = Guards(signals[cve], guards)
		guardIDs := make([]string, 0, len(ev.Guards))
		for _, g := range ev.Guards {
			guardIDs = append(guardIDs, g.ID)
		}

		out[cve] = Decision{
			CVEID:    cve,
			Verdict:  "not_relevant",
			RuleIDs:  ruleIDs,
			Guards:   guardIDs,
			Reason:   reason(ev),
			Evidence: ev,
		}
	}
	return out
}

// reason summarises the evidence in one line.
func reason(ev Evidence) string {
	parts := make([]string, 0, len(ev.Packages))
	for _, p := range ev.Packages {
		parts = append(parts, fmt.Sprintf("%s: %s (%s v%d)", p.Package, p.Detail, p.Rule, p.RuleVersion))
	}
	s := strings.Join(parts, "; ")
	if len(ev.Guards) > 0 {
		ids := make([]string, len(ev.Guards))
		for i, g := range ev.Guards {
			ids[i] = g.ID
		}
		s += " — blocked by " + strings.Join(ids, ", ")
	}
	return s
}

// compactCanonical writes the JSON document in a canonical form: decoded and
// re-encoded, which sorts object keys and drops insignificant whitespace.
func compactCanonical(w *bytes.Buffer, doc []byte) error {
	var v any
	if err := json.Unmarshal(doc, &v); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	w.Write(b)
	return nil
}
