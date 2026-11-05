package threatintel

import (
	"errors"
	"io"
	"strings"
	"testing"
)

const kevSample = `{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2026.11.04",
  "count": 3,
  "vulnerabilities": [
    {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
     "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
     "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
     "knownRansomwareCampaignUse": "Known", "notes": "https://example.org"},
    {"cveID": "cve-2020-29583", "vendorProject": "Zyxel", "product": "Multiple Products",
     "vulnerabilityName": "Hard-Coded Credentials", "dateAdded": "2021-11-03",
     "dueDate": "2022-05-03", "knownRansomwareCampaignUse": "Unknown", "notes": ""},
    {"cveID": "CVE-2021-44228", "vendorProject": "dup", "product": "dup",
     "vulnerabilityName": "dup", "dateAdded": "bad", "dueDate": "",
     "knownRansomwareCampaignUse": "Unknown", "notes": ""}
  ]
}`

func TestParseKEV(t *testing.T) {
	entries, version, err := ParseKEV(strings.NewReader(kevSample))
	if err != nil {
		t.Fatalf("ParseKEV: %v", err)
	}
	if version != "2026.11.04" {
		t.Errorf("version = %q", version)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2 (duplicate dropped): %+v", len(entries), entries)
	}
	log4j := entries[0]
	if log4j.CVEID != "CVE-2021-44228" || !log4j.KnownRansomwareUse || log4j.VendorProject != "Apache" ||
		log4j.DateAdded == nil || log4j.DateAdded.Format("2006-01-02") != "2021-12-10" ||
		log4j.DueDate == nil || log4j.DueDate.Format("2006-01-02") != "2021-12-24" {
		t.Errorf("log4j entry = %+v", log4j)
	}
	if entries[1].CVEID != "CVE-2020-29583" || entries[1].KnownRansomwareUse {
		t.Errorf("zyxel entry = %+v (ID upper-cased, ransomware unknown)", entries[1])
	}
}

func TestParseKEVCountMismatch(t *testing.T) {
	truncated := strings.Replace(kevSample, `"count": 3`, `"count": 1768`, 1)
	if _, _, err := ParseKEV(strings.NewReader(truncated)); err == nil {
		t.Fatal("a catalog whose count does not match its entries must be rejected")
	}
}

const epssSample = `#model_version:v2026.06.15,score_date:2026-11-04T12:03:12Z
cve,epss,percentile
CVE-1999-0001,0.04753,0.91909
CVE-2021-44228,0.99999,1.00000
`

func TestEPSSReader(t *testing.T) {
	er, err := NewEPSSReader(strings.NewReader(epssSample))
	if err != nil {
		t.Fatalf("NewEPSSReader: %v", err)
	}
	if er.ModelVersion != "v2026.06.15" || er.ScoreDate.Format("2006-01-02") != "2026-11-04" {
		t.Errorf("metadata = %q %v", er.ModelVersion, er.ScoreDate)
	}
	var got []EPSSScore
	for {
		row, err := er.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		got = append(got, row)
	}
	if len(got) != 2 || got[1].CVEID != "CVE-2021-44228" || got[1].EPSS != 0.99999 || got[0].Percentile != 0.91909 {
		t.Errorf("rows = %+v", got)
	}
}

func TestEPSSReaderRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"no metadata":    "cve,epss,percentile\nCVE-1999-0001,0.1,0.2\n",
		"wrong header":   "#score_date:2026-11-04T12:03:12Z\ncve,score,pct\n",
		"no score date":  "#model_version:v1\ncve,epss,percentile\n",
		"bad score date": "#score_date:yesterday\ncve,epss,percentile\n",
	}
	for name, input := range cases {
		if _, err := NewEPSSReader(strings.NewReader(input)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}

	rows := map[string]string{
		"not a CVE":    "GHSA-1234,0.1,0.2",
		"out of range": "CVE-2026-0001,1.5,0.2",
		"not a number": "CVE-2026-0001,abc,0.2",
		"field count":  "CVE-2026-0001,0.1",
	}
	for name, row := range rows {
		er, err := NewEPSSReader(strings.NewReader("#score_date:2026-11-04T12:03:12Z\ncve,epss,percentile\n" + row + "\n"))
		if err != nil {
			t.Fatalf("%s: NewEPSSReader: %v", name, err)
		}
		if _, err := er.Next(); err == nil || errors.Is(err, io.EOF) {
			t.Errorf("%s: expected a row error, got %v", name, err)
		}
	}
}
