package services_test

// Every read path of FindingService is executed against a real database here.
//
// The queries are assembled as SQL strings and read back with positional Scan
// destinations, so adding a column without adding a destination compiles, passes
// review, and only fails when that particular query runs — pgx reports
// "number of field descriptions must equal number of destinations". A column
// added to GetServersByCVE without its destination shipped in v1.5.0 and broke
// the AI assessment request, the CVE detail endpoint, /cves/:id/servers, Jira
// ticket creation and two MCP tools. Static counting cannot catch it: the
// queries are built from concatenated strings and contain nested SELECTs.
//
// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

const (
	testCVE     = "CVE-2026-31718"
	testPackage = "openssl"
)

// seedFinding inserts one server and one active finding, with every column the
// read paths surface populated so their values can be asserted too.
func seedFinding(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int64 {
	t.Helper()

	var serverID int64
	err := pool.QueryRow(ctx, `
		INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager)
		VALUES ('finding-test', 'ubuntu', '24.04', 'noble', '6.8.0-124-generic', 'amd64', 'dpkg')
		RETURNING id
	`).Scan(&serverID)
	if err != nil {
		t.Fatalf("insert server: %v", err)
	}

	// The link is passed as its own parameter rather than concatenated from
	// $2: reusing a parameter as both a column value and inside an expression
	// is what caused SQLSTATE 42P08 in the VEX and NVD syncers.
	_, err = pool.Exec(ctx, `
		INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state,
		                      fixed_in, fix_pocket, severity, summary, source_link, source_type,
		                      cvss3_score, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, '3.0.13-0ubuntu3.1', 'fix_available',
		        '3.0.13-0ubuntu3.2', 'esm-apps', 'high', 'a summary',
		        $4, 'usn', 7.5, NOW(), NOW())
	`, serverID, testCVE, testPackage, "https://ubuntu.com/security/"+testCVE)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}

	// An NVD row, so the CVSS join in the read paths has something to return.
	_, err = pool.Exec(ctx, `
		INSERT INTO cve_catalog (cve_id, description, cvss3_score, cvss3_severity)
		VALUES ($1, 'a description', 9.1, 'critical')
	`, testCVE)
	if err != nil {
		t.Fatalf("insert cve_catalog row: %v", err)
	}

	return serverID
}

// TestFindingServiceReadPathsExecute runs every read path. A column/destination
// mismatch in any of them fails here rather than in production.
func TestFindingServiceReadPathsExecute(t *testing.T) {
	pool, ctx := testdb.Setup(t, "finding_tests")
	serverID := seedFinding(t, ctx, pool)
	findingService := services.NewFindingService(pool)

	t.Run("GetAll", func(t *testing.T) {
		findings, total, err := findingService.GetAll(ctx, services.FindingFilter{Limit: 50})
		if err != nil {
			t.Fatalf("GetAll: %v", err)
		}
		if total != 1 || len(findings) != 1 {
			t.Fatalf("got %d findings (total %d), want 1", len(findings), total)
		}
		f := findings[0]
		if f.CVEID != testCVE || f.PackageName != testPackage {
			t.Errorf("wrong finding returned: %s / %s", f.CVEID, f.PackageName)
		}
		if f.FixPocket != "esm-apps" {
			t.Errorf("fixPocket = %q, want \"esm-apps\"", f.FixPocket)
		}
	})

	t.Run("GetAll with every filter set", func(t *testing.T) {
		cve, severity, vex := testCVE, "high", "not_affected"
		minCVSS := 1.0
		serverRef := serverID
		_, _, err := findingService.GetAll(ctx, services.FindingFilter{
			ServerID: &serverRef, CVEID: &cve, Severity: &severity,
			MinCVSS: &minCVSS, VexStatus: &vex, HideVendorAccepted: true, Search: "openssl",
			IncludeResolved: true, SortBy: "cvss3Score", SortOrder: "asc", Limit: 10,
		})
		if err != nil {
			t.Fatalf("GetAll with filters: %v", err)
		}
	})

	t.Run("GetAllGrouped", func(t *testing.T) {
		groups, total, err := findingService.GetAllGrouped(ctx, services.FindingFilter{Limit: 50})
		if err != nil {
			t.Fatalf("GetAllGrouped: %v", err)
		}
		if total != 1 || len(groups) != 1 {
			t.Fatalf("got %d groups (total %d), want 1", len(groups), total)
		}
		if len(groups[0].Packages) != 1 {
			t.Fatalf("got %d packages in the group, want 1", len(groups[0].Packages))
		}
		if got := groups[0].Packages[0].FixPocket; got != "esm-apps" {
			t.Errorf("grouped fixPocket = %q, want \"esm-apps\"", got)
		}
	})

	t.Run("GetTriageQueue cvss mode", func(t *testing.T) {
		_, _, err := findingService.GetTriageQueue(ctx, services.TriageFilterOptions{
			Mode: "cvss", CVSSThreshold: 7.0, Limit: 50,
		})
		if err != nil {
			t.Fatalf("GetTriageQueue: %v", err)
		}
	})

	t.Run("GetTriageQueue vendor_severity mode", func(t *testing.T) {
		_, _, err := findingService.GetTriageQueue(ctx, services.TriageFilterOptions{
			Mode: "vendor_severity", VendorSeverities: []string{"critical", "high"},
			IncludeUnrated: true, HideVexNotAffected: true, HideVendorAccepted: true, Limit: 50,
		})
		if err != nil {
			t.Fatalf("GetTriageQueue vendor mode: %v", err)
		}
	})

	t.Run("GetByID", func(t *testing.T) {
		findings, _, err := findingService.GetAll(ctx, services.FindingFilter{Limit: 1})
		if err != nil || len(findings) == 0 {
			t.Fatalf("could not obtain a finding id: %v", err)
		}

		f, err := findingService.GetByID(ctx, findings[0].ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if f.CVEID != testCVE {
			t.Errorf("GetByID returned %s, want %s", f.CVEID, testCVE)
		}
		if f.FixPocket != "esm-apps" {
			t.Errorf("fixPocket = %q, want \"esm-apps\"", f.FixPocket)
		}
		if f.Description != "a description" {
			t.Errorf("description = %q, want the NVD description", f.Description)
		}
	})

	// This is the path that broke: the AI assessment request, the CVE detail
	// endpoint, /cves/:id/servers, Jira ticket creation and two MCP tools all
	// go through it.
	t.Run("GetServersByCVE", func(t *testing.T) {
		findings, err := findingService.GetServersByCVE(ctx, testCVE)
		if err != nil {
			t.Fatalf("GetServersByCVE: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		f := findings[0]
		if f.ServerName != "finding-test" {
			t.Errorf("serverName = %q, want \"finding-test\"", f.ServerName)
		}
		if f.FixPocket != "esm-apps" {
			t.Errorf("fixPocket = %q, want \"esm-apps\"", f.FixPocket)
		}
		if f.FixedIn != "3.0.13-0ubuntu3.2" || f.FixState != "fix_available" {
			t.Errorf("columns are shifted: fixedIn=%q fixState=%q", f.FixedIn, f.FixState)
		}
	})

	t.Run("MarkResolved", func(t *testing.T) {
		// No active keys reported, so the seeded finding is resolved.
		resolved, err := findingService.MarkResolved(ctx, serverID, nil, time.Now())
		if err != nil {
			t.Fatalf("MarkResolved: %v", err)
		}
		if resolved != 1 {
			t.Errorf("resolved %d findings, want 1", resolved)
		}
		if findings, err := findingService.GetServersByCVE(ctx, testCVE); err != nil {
			t.Fatalf("GetServersByCVE after resolve: %v", err)
		} else if len(findings) != 0 {
			t.Errorf("resolved findings are still reported as active: %d", len(findings))
		}
	})
}

// TestHideVendorAccepted checks which findings survive the vendor-accepted
// filter, and that the triage queue applies it per finding before grouping by
// CVE: a CVE stays queued while any of its findings is still actionable.
func TestHideVendorAccepted(t *testing.T) {
	pool, ctx := testdb.Setup(t, "vendor_accepted_tests")
	findingService := services.NewFindingService(pool)

	var serverID int64
	err := pool.QueryRow(ctx, `
		INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager)
		VALUES ('vendor-accepted-test', 'ubuntu', '24.04', 'noble', '6.8.0-124-generic', 'amd64', 'dpkg')
		RETURNING id
	`).Scan(&serverID)
	if err != nil {
		t.Fatalf("insert server: %v", err)
	}

	const (
		cveAccepted = "CVE-2026-0001" // every finding is vendor-accepted
		cveMixed    = "CVE-2026-0002" // one finding accepted, one still affected
		cveUnset    = "CVE-2026-0003" // fix_state never written
		cveFixable  = "CVE-2026-0004" // a fix is available
	)
	rows := []struct {
		cve, pkg string
		fixState *string
	}{
		{cveAccepted, "libfoo1", ptr("will_not_fix")},
		{cveAccepted, "libfoo-dev", ptr("deferred")},
		{cveMixed, "libbar1", ptr("will_not_fix")},
		{cveMixed, "bar", ptr("affected")},
		{cveUnset, "baz", nil},
		{cveFixable, "qux", ptr("fix_available")},
	}
	for _, r := range rows {
		_, err := pool.Exec(ctx, `
			INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state,
			                      severity, source_type, cvss3_score, first_seen_at, last_seen_at)
			VALUES ($1, $2, $3, '1.0', $4, 'high', 'usn', 7.5, NOW(), NOW())
		`, serverID, r.cve, r.pkg, r.fixState)
		if err != nil {
			t.Fatalf("insert finding %s/%s: %v", r.cve, r.pkg, err)
		}
	}

	t.Run("GetAll", func(t *testing.T) {
		findings, total, err := findingService.GetAll(ctx, services.FindingFilter{HideVendorAccepted: true, Limit: 50})
		if err != nil {
			t.Fatalf("GetAll: %v", err)
		}
		got := map[string]bool{}
		for _, f := range findings {
			got[f.CVEID+"|"+f.PackageName] = true
		}
		want := []string{cveMixed + "|bar", cveUnset + "|baz", cveFixable + "|qux"}
		if total != len(want) || len(findings) != len(want) {
			t.Fatalf("got %d findings (total %d), want %d: %v", len(findings), total, len(want), got)
		}
		for _, k := range want {
			if !got[k] {
				t.Errorf("finding %s is missing", k)
			}
		}
	})

	t.Run("GetAll without the filter", func(t *testing.T) {
		_, total, err := findingService.GetAll(ctx, services.FindingFilter{Limit: 50})
		if err != nil {
			t.Fatalf("GetAll: %v", err)
		}
		if total != len(rows) {
			t.Errorf("total = %d, want %d", total, len(rows))
		}
	})

	t.Run("GetAllGrouped", func(t *testing.T) {
		groups, total, err := findingService.GetAllGrouped(ctx, services.FindingFilter{HideVendorAccepted: true, Limit: 50})
		if err != nil {
			t.Fatalf("GetAllGrouped: %v", err)
		}
		if total != 3 || len(groups) != 3 {
			t.Fatalf("got %d groups (total %d), want 3", len(groups), total)
		}
		for _, g := range groups {
			if g.CVEID == cveAccepted {
				t.Errorf("%s is listed although all its findings are vendor-accepted", cveAccepted)
			}
			if g.CVEID == cveMixed && len(g.Packages) != 1 {
				t.Errorf("%s lists %d packages, want only the affected one", cveMixed, len(g.Packages))
			}
		}
	})

	triageCVEs := func(t *testing.T, hide bool) map[string]bool {
		t.Helper()
		findings, total, err := findingService.GetTriageQueue(ctx, services.TriageFilterOptions{
			Mode: "cvss", CVSSThreshold: 7.0, HideVendorAccepted: hide, Limit: 50,
		})
		if err != nil {
			t.Fatalf("GetTriageQueue: %v", err)
		}
		cves := map[string]bool{}
		for _, f := range findings {
			cves[f.CVEID] = true
		}
		if total != len(cves) {
			t.Errorf("total = %d, but %d CVEs returned", total, len(cves))
		}
		return cves
	}

	t.Run("GetTriageQueue", func(t *testing.T) {
		cves := triageCVEs(t, true)
		if cves[cveAccepted] {
			t.Errorf("%s is queued although all its findings are vendor-accepted", cveAccepted)
		}
		for _, cve := range []string{cveMixed, cveUnset, cveFixable} {
			if !cves[cve] {
				t.Errorf("%s is missing from the triage queue", cve)
			}
		}
	})

	t.Run("GetTriageQueue without the filter", func(t *testing.T) {
		if cves := triageCVEs(t, false); len(cves) != 4 {
			t.Errorf("got %d CVEs, want all 4", len(cves))
		}
	})

	// The queue is computed live, so a finding whose vendor status changes
	// back to actionable brings its CVE back without any further step.
	t.Run("GetTriageQueue after the vendor status changes", func(t *testing.T) {
		_, err := pool.Exec(ctx, `
			UPDATE findings SET fix_state = 'fix_available' WHERE cve_id = $1 AND package_name = 'libfoo1'
		`, cveAccepted)
		if err != nil {
			t.Fatalf("update finding: %v", err)
		}
		if cves := triageCVEs(t, true); !cves[cveAccepted] {
			t.Errorf("%s did not return to the triage queue", cveAccepted)
		}
	})
}

func ptr(s string) *string { return &s }
