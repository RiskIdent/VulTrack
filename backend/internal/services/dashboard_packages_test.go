package services_test

// Covers the dashboard's "Pending Assessment" count and the installed-package
// listing behind the APT Packages page.
//
// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"testing"

	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

// The dashboard used to count CVEs by findings.cvss3_score, a column the scanner
// never fills (the score lives in cve_catalog), so it always showed 0. It must
// now report exactly the triage queue's total, under whichever filter mode is
// configured.
func TestDashboardPendingMatchesTriageQueue(t *testing.T) {
	pool, ctx := testdb.Setup(t, "dashboard_pending_tests")
	findingService := services.NewFindingService(pool)
	statsService := services.NewStatsService(pool)

	var serverID int64
	err := pool.QueryRow(ctx, `
		INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager)
		VALUES ('dashboard-test', 'ubuntu', '24.04', 'noble', '6.8.0-124-generic', 'amd64', 'dpkg')
		RETURNING id
	`).Scan(&serverID)
	if err != nil {
		t.Fatalf("insert server: %v", err)
	}

	// No finding carries its own cvss3_score, as in production.
	findings := []struct{ cve, pkg, severity string }{
		{"CVE-2026-2001", "pkg-a", "high"},   // NVD 9.8, open
		{"CVE-2026-2001", "pkg-b", "high"},   // same CVE on another package
		{"CVE-2026-2002", "pkg-c", "medium"}, // NVD 7.5, open
		{"CVE-2026-2003", "pkg-d", "high"},   // NVD 8.1, already assessed
		{"CVE-2026-2004", "pkg-e", "low"},    // NVD 4.0, below the threshold
	}
	for _, f := range findings {
		_, err := pool.Exec(ctx, `
			INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state,
			                      severity, source_type, first_seen_at, last_seen_at)
			VALUES ($1, $2, $3, '1.0', 'affected', $4, 'usn', NOW(), NOW())
		`, serverID, f.cve, f.pkg, f.severity)
		if err != nil {
			t.Fatalf("insert finding %s/%s: %v", f.cve, f.pkg, err)
		}
	}
	for cve, score := range map[string]float64{
		"CVE-2026-2001": 9.8, "CVE-2026-2002": 7.5, "CVE-2026-2003": 8.1, "CVE-2026-2004": 4.0,
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO cve_catalog (cve_id, description, cvss3_score) VALUES ($1, '', $2)`, cve, score); err != nil {
			t.Fatalf("insert catalog %s: %v", cve, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO assessments (cve_id, status) VALUES ('CVE-2026-2003', 'not_relevant')`); err != nil {
		t.Fatalf("insert assessment: %v", err)
	}

	cases := []struct {
		name string
		opts services.TriageFilterOptions
		want int
	}{
		{"cvss mode", services.TriageFilterOptions{Mode: "cvss", CVSSThreshold: 7.0}, 2},
		{"vendor severity mode", services.TriageFilterOptions{Mode: "vendor_severity", VendorSeverities: []string{"critical", "high"}}, 1},
		{"vendor severity mode, nothing selected", services.TriageFilterOptions{Mode: "vendor_severity"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			stats, err := statsService.GetDashboardStats(ctx, &opts)
			if err != nil {
				t.Fatalf("GetDashboardStats: %v", err)
			}
			opts.Limit = 50
			_, queueTotal, err := findingService.GetTriageQueue(ctx, opts)
			if err != nil {
				t.Fatalf("GetTriageQueue: %v", err)
			}
			if stats.PendingAssessments != tc.want || queueTotal != tc.want {
				t.Errorf("pending = %d, triage queue total = %d, want %d", stats.PendingAssessments, queueTotal, tc.want)
			}
		})
	}

	t.Run("without triage options", func(t *testing.T) {
		stats, err := statsService.GetDashboardStats(ctx, nil)
		if err != nil {
			t.Fatalf("GetDashboardStats: %v", err)
		}
		if stats.PendingAssessments != 0 || stats.ActiveFindings != len(findings) {
			t.Errorf("pending = %d, active = %d; want 0 and %d", stats.PendingAssessments, stats.ActiveFindings, len(findings))
		}
	})
}

func TestListInstalledPackages(t *testing.T) {
	pool, ctx := testdb.Setup(t, "installed_packages_tests")
	packageService := services.NewPackageService(pool)

	servers := map[string]int64{}
	for _, s := range []struct{ name, release, codename string }{
		{"web-01", "24.04", "noble"},
		{"db-01", "22.04", "jammy"},
	} {
		var id int64
		err := pool.QueryRow(ctx, `
			INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager)
			VALUES ($1, 'ubuntu', $2, $3, '6.8.0', 'amd64', 'dpkg')
			RETURNING id
		`, s.name, s.release, s.codename).Scan(&id)
		if err != nil {
			t.Fatalf("insert server %s: %v", s.name, err)
		}
		servers[s.name] = id
	}

	packages := []struct {
		server, name, version, arch, source string
		removed                             bool
	}{
		{"web-01", "openssl", "3.0.13-0ubuntu3.4", "amd64", "openssl", false},
		{"web-01", "libssl3t64", "3.0.13-0ubuntu3.4", "amd64", "openssl", false},
		{"web-01", "nginx", "1.24.0-2ubuntu7", "amd64", "nginx", false},
		{"web-01", "old_pkg", "1.0", "all", "old", true}, // removed: never listed
		{"db-01", "openssl", "3.0.2-0ubuntu1.18", "amd64", "openssl", false},
		{"db-01", "postgresql-16", "16.4-1", "amd64", "postgresql-16", false},
		{"db-01", "tzdata", "2024a-0ubuntu0.22.04", "all", "tzdata", false},
	}
	for _, p := range packages {
		_, err := pool.Exec(ctx, `
			INSERT INTO server_packages (server_id, name, version, arch, source_package, first_seen_at, last_seen_at, removed_at)
			VALUES ($1, $2, $3, $4, $5, NOW(), NOW(), CASE WHEN $6::bool THEN NOW() END)
		`, servers[p.server], p.name, p.version, p.arch, p.source, p.removed)
		if err != nil {
			t.Fatalf("insert package %s/%s: %v", p.server, p.name, err)
		}
	}

	list := func(t *testing.T, f services.InstalledPackageFilter) ([]string, int) {
		t.Helper()
		got, total, err := packageService.ListInstalled(ctx, f)
		if err != nil {
			t.Fatalf("ListInstalled: %v", err)
		}
		keys := make([]string, len(got))
		for i, p := range got {
			keys[i] = p.ServerName + "/" + p.Name
		}
		return keys, total
	}
	equal := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	cases := []struct {
		name   string
		filter services.InstalledPackageFilter
		want   []string
	}{
		{"all installed, by name then server", services.InstalledPackageFilter{},
			[]string{"web-01/libssl3t64", "web-01/nginx", "db-01/openssl", "web-01/openssl", "db-01/postgresql-16", "db-01/tzdata"}},
		{"name, case-insensitive", services.InstalledPackageFilter{Name: "OpenSSL"},
			[]string{"db-01/openssl", "web-01/openssl"}},
		{"version", services.InstalledPackageFilter{Version: "3.0.13"},
			[]string{"web-01/libssl3t64", "web-01/openssl"}},
		{"source package", services.InstalledPackageFilter{SourcePackage: "openssl", Server: "web"},
			[]string{"web-01/libssl3t64", "web-01/openssl"}},
		{"arch", services.InstalledPackageFilter{Arch: "all"},
			[]string{"db-01/tzdata"}},
		{"os by codename", services.InstalledPackageFilter{OS: "jammy"},
			[]string{"db-01/openssl", "db-01/postgresql-16", "db-01/tzdata"}},
		{"os by release", services.InstalledPackageFilter{OS: "24.04"},
			[]string{"web-01/libssl3t64", "web-01/nginx", "web-01/openssl"}},
		{"underscore is literal, not a wildcard", services.InstalledPackageFilter{Name: "l_b"},
			[]string{}},
		{"sort by server desc", services.InstalledPackageFilter{Name: "openssl", SortBy: "serverName", SortOrder: "desc"},
			[]string{"web-01/openssl", "db-01/openssl"}},
		{"unknown sort column falls back to name", services.InstalledPackageFilter{Server: "db", SortBy: "1; DROP TABLE servers"},
			[]string{"db-01/openssl", "db-01/postgresql-16", "db-01/tzdata"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, total := list(t, tc.filter)
			if !equal(got, tc.want) || total != len(tc.want) {
				t.Errorf("got %v (total %d), want %v", got, total, tc.want)
			}
		})
	}

	t.Run("pagination", func(t *testing.T) {
		got, total := list(t, services.InstalledPackageFilter{Limit: 2, Offset: 2})
		if total != 6 || !equal(got, []string{"db-01/openssl", "web-01/openssl"}) {
			t.Errorf("got %v (total %d)", got, total)
		}
	})

	t.Run("exact name for the detail page", func(t *testing.T) {
		got, total := list(t, services.InstalledPackageFilter{ExactName: "openssl"})
		if total != 2 || !equal(got, []string{"db-01/openssl", "web-01/openssl"}) {
			t.Errorf("got %v (total %d)", got, total)
		}
		// libssl3t64 contains "ssl" but is not the package itself.
		got, _ = list(t, services.InstalledPackageFilter{ExactName: "ssl"})
		if len(got) != 0 {
			t.Errorf("exact name matched %v", got)
		}
	})

	t.Run("summaries: one row per package", func(t *testing.T) {
		got, total, err := packageService.ListPackageSummaries(ctx, services.InstalledPackageFilter{})
		if err != nil {
			t.Fatalf("ListPackageSummaries: %v", err)
		}
		if total != 5 || len(got) != 5 {
			t.Fatalf("got %d summaries (total %d), want 5", len(got), total)
		}
		openssl := got[2]
		if openssl.Name != "openssl" || openssl.ServerCount != 2 ||
			!equal(openssl.Versions, []string{"3.0.13-0ubuntu3.4", "3.0.2-0ubuntu1.18"}) ||
			!equal(openssl.SourcePackages, []string{"openssl"}) || !equal(openssl.Archs, []string{"amd64"}) {
			t.Errorf("openssl summary = %+v", openssl)
		}
	})

	t.Run("summaries: filters apply before grouping", func(t *testing.T) {
		got, total, err := packageService.ListPackageSummaries(ctx, services.InstalledPackageFilter{Version: "3.0.2"})
		if err != nil {
			t.Fatalf("ListPackageSummaries: %v", err)
		}
		if total != 1 || got[0].Name != "openssl" || got[0].ServerCount != 1 || !equal(got[0].Versions, []string{"3.0.2-0ubuntu1.18"}) {
			t.Errorf("got %+v (total %d)", got, total)
		}
	})

	t.Run("summaries: sort by server count", func(t *testing.T) {
		got, _, err := packageService.ListPackageSummaries(ctx, services.InstalledPackageFilter{SortBy: "serverCount", SortOrder: "desc", Limit: 1})
		if err != nil {
			t.Fatalf("ListPackageSummaries: %v", err)
		}
		if len(got) != 1 || got[0].Name != "openssl" {
			t.Errorf("got %+v", got)
		}
	})

	t.Run("os is rendered for display", func(t *testing.T) {
		got, _, err := packageService.ListInstalled(ctx, services.InstalledPackageFilter{Name: "nginx"})
		if err != nil {
			t.Fatalf("ListInstalled: %v", err)
		}
		if len(got) != 1 || got[0].OS != "ubuntu 24.04 (noble)" {
			t.Errorf("got %+v", got)
		}
	})
}
