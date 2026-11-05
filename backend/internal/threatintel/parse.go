// Package threatintel syncs two exploitation signals into VulTrack: the CISA
// Known Exploited Vulnerabilities catalog (KEV) and FIRST's Exploit Prediction
// Scoring System (EPSS). Both are global per CVE; they prioritise the triage
// queue and act as guards for automated assessment
// (docs/AUTO_ASSESSMENT_PLAN.md).
package threatintel

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// KEVEntry is one vulnerability of the CISA KEV catalog.
type KEVEntry struct {
	CVEID              string
	VendorProject      string
	Product            string
	VulnerabilityName  string
	DateAdded          *time.Time
	DueDate            *time.Time
	KnownRansomwareUse bool
	Notes              string
}

// kevCatalog mirrors the parts of known_exploited_vulnerabilities.json we use.
type kevCatalog struct {
	CatalogVersion  string `json:"catalogVersion"`
	Count           int    `json:"count"`
	Vulnerabilities []struct {
		CVEID                      string `json:"cveID"`
		VendorProject              string `json:"vendorProject"`
		Product                    string `json:"product"`
		VulnerabilityName          string `json:"vulnerabilityName"`
		DateAdded                  string `json:"dateAdded"`
		DueDate                    string `json:"dueDate"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		Notes                      string `json:"notes"`
	} `json:"vulnerabilities"`
}

// ParseKEV decodes the KEV catalog JSON. It fails when the catalog's own count
// does not match the number of entries, so a truncated download is never
// mistaken for a catalog that shrank.
func ParseKEV(r io.Reader) (entries []KEVEntry, catalogVersion string, err error) {
	var cat kevCatalog
	if err := json.NewDecoder(r).Decode(&cat); err != nil {
		return nil, "", fmt.Errorf("decode KEV catalog: %w", err)
	}
	if cat.Count != len(cat.Vulnerabilities) {
		return nil, "", fmt.Errorf("KEV catalog lists %d entries but says count %d", len(cat.Vulnerabilities), cat.Count)
	}

	seen := make(map[string]bool, len(cat.Vulnerabilities))
	for _, v := range cat.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CVEID))
		if !strings.HasPrefix(id, "CVE-") || seen[id] {
			continue
		}
		seen[id] = true
		entries = append(entries, KEVEntry{
			CVEID:              id,
			VendorProject:      v.VendorProject,
			Product:            v.Product,
			VulnerabilityName:  v.VulnerabilityName,
			DateAdded:          parseDate(v.DateAdded),
			DueDate:            parseDate(v.DueDate),
			KnownRansomwareUse: strings.EqualFold(strings.TrimSpace(v.KnownRansomwareCampaignUse), "known"),
			Notes:              v.Notes,
		})
	}
	return entries, cat.CatalogVersion, nil
}

func parseDate(s string) *time.Time {
	t, err := time.Parse("2006-01-02", strings.TrimSpace(s))
	if err != nil {
		return nil
	}
	return &t
}

// EPSSScore is one row of the EPSS score file.
type EPSSScore struct {
	CVEID      string
	EPSS       float64
	Percentile float64
}

// EPSSReader streams the EPSS CSV (already decompressed):
//
//	#model_version:v2026.06.15,score_date:2026-11-04T12:03:12Z
//	cve,epss,percentile
//	CVE-1999-0001,0.04753,0.91909
type EPSSReader struct {
	ModelVersion string
	ScoreDate    time.Time
	csv          *csv.Reader
}

// NewEPSSReader reads the metadata comment and the header line.
func NewEPSSReader(r io.Reader) (*EPSSReader, error) {
	br := bufio.NewReader(r)
	meta, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read EPSS metadata line: %w", err)
	}
	er := &EPSSReader{}
	if !strings.HasPrefix(meta, "#") {
		return nil, fmt.Errorf("EPSS file does not start with a metadata comment")
	}
	for _, field := range strings.Split(strings.TrimSpace(strings.TrimPrefix(meta, "#")), ",") {
		key, value, _ := strings.Cut(field, ":")
		switch key {
		case "model_version":
			er.ModelVersion = value
		case "score_date":
			t, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return nil, fmt.Errorf("parse EPSS score_date %q: %w", value, err)
			}
			er.ScoreDate = t
		}
	}
	if er.ScoreDate.IsZero() {
		return nil, fmt.Errorf("EPSS metadata has no score_date")
	}

	er.csv = csv.NewReader(br)
	er.csv.FieldsPerRecord = 3
	header, err := er.csv.Read()
	if err != nil {
		return nil, fmt.Errorf("read EPSS header: %w", err)
	}
	if strings.Join(header, ",") != "cve,epss,percentile" {
		return nil, fmt.Errorf("unexpected EPSS header %q", strings.Join(header, ","))
	}
	return er, nil
}

// Next returns the next score, or io.EOF at the end of the file.
func (er *EPSSReader) Next() (EPSSScore, error) {
	rec, err := er.csv.Read()
	if errors.Is(err, io.EOF) {
		return EPSSScore{}, io.EOF
	}
	if err != nil {
		return EPSSScore{}, fmt.Errorf("read EPSS row: %w", err)
	}
	epss, err1 := strconv.ParseFloat(rec[1], 64)
	pct, err2 := strconv.ParseFloat(rec[2], 64)
	if err1 != nil || err2 != nil || !strings.HasPrefix(rec[0], "CVE-") ||
		epss < 0 || epss > 1 || pct < 0 || pct > 1 {
		return EPSSScore{}, fmt.Errorf("invalid EPSS row %q", strings.Join(rec, ","))
	}
	return EPSSScore{CVEID: rec[0], EPSS: epss, Percentile: pct}, nil
}
