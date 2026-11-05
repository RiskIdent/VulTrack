package services_test

// KEV and EPSS in the findings views: filters, sorting, the triage queue's
// priority order and the CVE-level lookup.
//
// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"strings"
	"testing"

	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

func TestThreatIntelInFindings(t *testing.T) {
	pool, ctx := testdb.Setup(t, "threat_intel_findings_tests")
	findingService := services.NewFindingService(pool)
	statsService := services.NewStatsService(pool)
	threatIntelService := services.NewThreatIntelService(pool)

	var serverID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager)
		VALUES ('ti-test', 'ubuntu', '24.04', 'noble', '6.8.0', 'amd64', 'dpkg') RETURNING id
	`).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}

	// cve, cvss, in KEV, EPSS (-1 = none)
	cves := []struct {
		id   string
		cvss float64
		kev  bool
		epss float64
	}{
		{"CVE-2026-3001", 9.8, false, 0.02}, // highest CVSS, low EPSS
		{"CVE-2026-3002", 7.5, true, 0.10},  // KEV
		{"CVE-2026-3003", 8.0, false, 0.90}, // high EPSS
		{"CVE-2026-3004", 8.8, false, -1},   // no EPSS
		{"CVE-2026-3005", 7.2, true, 0.50},  // KEV with higher EPSS
	}
	for _, c := range cves {
		if _, err := pool.Exec(ctx, `
			INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state, severity, source_type, first_seen_at, last_seen_at)
			VALUES ($1, $2, 'pkg', '1.0', 'affected', 'high', 'usn', NOW(), NOW())
		`, serverID, c.id); err != nil {
			t.Fatalf("insert finding: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO cve_catalog (cve_id, description, cvss3_score) VALUES ($1, '', $2)`, c.id, c.cvss); err != nil {
			t.Fatalf("insert catalog: %v", err)
		}
		if c.kev {
			if _, err := pool.Exec(ctx, `
				INSERT INTO kev_entries (cve_id, vendor_project, vulnerability_name, date_added, due_date, known_ransomware_use)
				VALUES ($1, 'Vendor', 'Name', '2026-10-01', '2026-10-22', $2)
			`, c.id, c.id == "CVE-2026-3005"); err != nil {
				t.Fatalf("insert kev: %v", err)
			}
		}
		if c.epss >= 0 {
			if _, err := pool.Exec(ctx, `INSERT INTO epss_scores (cve_id, epss, percentile, score_date) VALUES ($1, $2, 0.5, '2026-11-04')`, c.id, c.epss); err != nil {
				t.Fatalf("insert epss: %v", err)
			}
		}
	}

	ids := func(n int, at func(int) string) string {
		out := make([]string, n)
		for i := range out {
			out[i] = strings.TrimPrefix(at(i), "CVE-2026-")
		}
		return strings.Join(out, ",")
	}

	t.Run("triage queue is ordered by KEV, EPSS, CVSS", func(t *testing.T) {
		findings, total, err := findingService.GetTriageQueue(ctx, services.TriageFilterOptions{Mode: "cvss", CVSSThreshold: 7.0, Limit: 50})
		if err != nil {
			t.Fatalf("GetTriageQueue: %v", err)
		}
		got := ids(len(findings), func(i int) string { return findings[i].CVEID })
		if total != 5 || got != "3005,3002,3003,3001,3004" {
			t.Errorf("order = %s (total %d), want 3005,3002,3003,3001,3004", got, total)
		}
		if !findings[0].InKEV || !findings[0].KEVRansomware || findings[0].EPSS == nil || *findings[0].EPSS != 0.5 ||
			findings[0].KEVDueDate == nil || findings[0].KEVDueDate.Format("2006-01-02") != "2026-10-22" {
			t.Errorf("first entry threat intel = %+v", findings[0].ThreatIntel)
		}
		if findings[4].InKEV || findings[4].EPSS != nil {
			t.Errorf("last entry should have neither KEV nor EPSS: %+v", findings[4].ThreatIntel)
		}
	})

	t.Run("triage pagination follows the priority order", func(t *testing.T) {
		page, _, err := findingService.GetTriageQueue(ctx, services.TriageFilterOptions{Mode: "cvss", CVSSThreshold: 7.0, Limit: 2, Offset: 2})
		if err != nil {
			t.Fatalf("GetTriageQueue: %v", err)
		}
		if got := ids(len(page), func(i int) string { return page[i].CVEID }); got != "3003,3001" {
			t.Errorf("page 2 = %s, want 3003,3001", got)
		}
	})

	t.Run("KEV only filter", func(t *testing.T) {
		findings, total, err := findingService.GetAll(ctx, services.FindingFilter{KEVOnly: true, SortBy: "cveId", SortOrder: "asc", Limit: 50})
		if err != nil {
			t.Fatalf("GetAll: %v", err)
		}
		if got := ids(len(findings), func(i int) string { return findings[i].CVEID }); total != 2 || got != "3002,3005" {
			t.Errorf("got %s (total %d)", got, total)
		}
	})

	t.Run("min EPSS filter and EPSS sort", func(t *testing.T) {
		min := 0.10
		findings, total, err := findingService.GetAll(ctx, services.FindingFilter{MinEPSS: &min, SortBy: "epss", SortOrder: "desc", Limit: 50})
		if err != nil {
			t.Fatalf("GetAll: %v", err)
		}
		if got := ids(len(findings), func(i int) string { return findings[i].CVEID }); total != 3 || got != "3003,3005,3002" {
			t.Errorf("got %s (total %d)", got, total)
		}
	})

	t.Run("grouped view carries the same signals and filters", func(t *testing.T) {
		groups, total, err := findingService.GetAllGrouped(ctx, services.FindingFilter{KEVOnly: true, SortBy: "epss", SortOrder: "desc", Limit: 50})
		if err != nil {
			t.Fatalf("GetAllGrouped: %v", err)
		}
		if got := ids(len(groups), func(i int) string { return groups[i].CVEID }); total != 2 || got != "3005,3002" {
			t.Errorf("got %s (total %d)", got, total)
		}
		if !groups[0].InKEV || groups[0].EPSS == nil {
			t.Errorf("group threat intel = %+v", groups[0].ThreatIntel)
		}
	})

	t.Run("grouped pagination: page content and total, also past the end", func(t *testing.T) {
		page, total, err := findingService.GetAllGrouped(ctx, services.FindingFilter{SortBy: "cveId", SortOrder: "asc", Limit: 2, Offset: 2})
		if err != nil {
			t.Fatalf("GetAllGrouped: %v", err)
		}
		if got := ids(len(page), func(i int) string { return page[i].CVEID }); total != 5 || got != "3003,3004" {
			t.Errorf("page 2 = %s (total %d), want 3003,3004 of 5", got, total)
		}
		if len(page) == 2 && len(page[0].Packages) != 1 {
			t.Errorf("group details missing: %+v", page[0])
		}
		empty, total, err := findingService.GetAllGrouped(ctx, services.FindingFilter{SortBy: "cveId", SortOrder: "asc", Limit: 2, Offset: 50})
		if err != nil || len(empty) != 0 || total != 5 {
			t.Errorf("past the end: %d groups, total %d, err %v", len(empty), total, err)
		}
	})

	t.Run("finding detail", func(t *testing.T) {
		var id int64
		if err := pool.QueryRow(ctx, `SELECT id FROM findings WHERE cve_id = 'CVE-2026-3002'`).Scan(&id); err != nil {
			t.Fatalf("lookup: %v", err)
		}
		f, err := findingService.GetByID(ctx, id)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if !f.InKEV || f.EPSS == nil || *f.EPSS != 0.10 {
			t.Errorf("detail threat intel = %+v", f.ThreatIntel)
		}
	})

	t.Run("CVE lookup", func(t *testing.T) {
		ti, err := threatIntelService.GetForCVE(ctx, "CVE-2026-3005")
		if err != nil {
			t.Fatalf("GetForCVE: %v", err)
		}
		if !ti.InKEV || ti.KEVVendorProject != "Vendor" || ti.EPSSScoreDate == nil {
			t.Errorf("got %+v", ti)
		}
		none, err := threatIntelService.GetForCVE(ctx, "CVE-2026-9999")
		if err != nil || none.InKEV || none.EPSS != nil {
			t.Errorf("unknown CVE = %+v, err %v", none, err)
		}
	})

	t.Run("top CVEs", func(t *testing.T) {
		top, err := statsService.GetTopCVEs(ctx, 10)
		if err != nil {
			t.Fatalf("GetTopCVEs: %v", err)
		}
		kev := 0
		for _, c := range top {
			if c.InKEV {
				kev++
			}
		}
		if len(top) != 5 || kev != 2 {
			t.Errorf("got %d CVEs, %d in KEV", len(top), kev)
		}
	})
}
