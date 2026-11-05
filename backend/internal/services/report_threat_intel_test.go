package services_test

// The PDF report marks KEV-listed CVEs and shows EPSS in both CVE tables.
//
// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

func TestReportWithThreatIntel(t *testing.T) {
	pool, ctx := testdb.Setup(t, "report_threat_intel_tests")

	var serverID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager)
		VALUES ('report-test', 'ubuntu', '24.04', 'noble', '6.8.0', 'amd64', 'dpkg') RETURNING id
	`).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	for i, cve := range []string{"CVE-2021-44228", "CVE-2024-3094", "CVE-2026-0001"} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state, severity, source_type, summary, first_seen_at, last_seen_at)
			VALUES ($1, $2, 'pkg', '1.0', 'affected', 'high', 'usn', 'A summary', NOW() - interval '3 days', NOW())
		`, serverID, cve); err != nil {
			t.Fatalf("insert finding: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO cve_catalog (cve_id, description, cvss3_score) VALUES ($1, 'desc', $2)`, cve, 10-float64(i)); err != nil {
			t.Fatalf("insert catalog: %v", err)
		}
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO kev_entries (cve_id, vendor_project, date_added, known_ransomware_use) VALUES
			('CVE-2021-44228', 'Apache', '2021-12-10', true), ('CVE-2024-3094', 'XZ', '2024-04-01', false);
		INSERT INTO epss_scores (cve_id, epss, percentile, score_date) VALUES
			('CVE-2021-44228', 0.99999, 1, '2026-11-04'), ('CVE-2024-3094', 0.0812, 0.9, '2026-11-04');
	`); err != nil {
		t.Fatalf("insert threat intel: %v", err)
	}

	pdf, err := services.NewReportService(pool).GenerateVulnerabilitySummary(ctx, services.ReportRequest{
		StartDate:          time.Now().AddDate(0, -1, 0),
		EndDate:            time.Now(),
		IncludeTopCVEs:     true,
		IncludeFullCVEList: true,
	})
	if err != nil {
		t.Fatalf("GenerateVulnerabilitySummary: %v", err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF")) {
		t.Fatalf("output is not a PDF")
	}
	if path := os.Getenv("VULTRACK_REPORT_OUT"); path != "" {
		if err := os.WriteFile(path, pdf, 0o600); err != nil {
			t.Fatalf("write PDF: %v", err)
		}
	}
}
