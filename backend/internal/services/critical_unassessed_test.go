package services_test

// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"testing"

	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

func TestCriticalUnassessed(t *testing.T) {
	pool, ctx := testdb.Setup(t, "critical_unassessed_tests")
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	var on, off int64
	pool.QueryRow(ctx, `INSERT INTO servers (name, os_family, os_release) VALUES ('on', 'ubuntu', '24.04') RETURNING id`).Scan(&on)
	pool.QueryRow(ctx, `INSERT INTO servers (name, os_family, os_release, disabled_at) VALUES ('off', 'ubuntu', '24.04', NOW()) RETURNING id`).Scan(&off)
	add := func(server int64, cve string) {
		exec(`INSERT INTO findings (server_id, cve_id, package_name, severity, first_seen_at, last_seen_at) VALUES ($1, $2, 'kernel', 'critical', NOW(), NOW())`, server, cve)
	}
	add(on, "CVE-OPEN")     // counts
	add(on, "CVE-ASSESSED") // CVE assessment
	add(on, "CVE-OVERRIDE") // per-server decision
	add(on, "CVE-AUTO")     // automated decision in effect
	add(on, "CVE-SHADOW")   // automated decision of a rule not in effect: counts
	add(off, "CVE-OPEN")    // disabled server
	exec(`INSERT INTO findings (server_id, cve_id, package_name, severity, first_seen_at, last_seen_at) VALUES ($1, 'CVE-HIGH', 'p', 'high', NOW(), NOW())`, on)
	exec(`INSERT INTO assessments (cve_id, status) VALUES ('CVE-ASSESSED', 'accepted_risk')`)
	exec(`INSERT INTO assessment_overrides (server_id, cve_id, status) VALUES ($1, 'CVE-OVERRIDE', 'not_relevant')`, on)
	exec(`INSERT INTO auto_decisions (server_id, cve_id, rule_ids, reason) VALUES ($1, 'CVE-AUTO', '{R-KMOD}', 'x'), ($1, 'CVE-SHADOW', '{AI-PRE}', 'x')`, on)

	opts := services.TriageFilterOptions{Mode: "cvss", CVSSThreshold: 7, AutoActiveRules: []string{"R-KMOD"}}
	stats, err := services.NewStatsService(pool).GetDashboardStats(ctx, &opts)
	if err != nil {
		t.Fatal(err)
	}
	if stats.CriticalFindings != 6 || stats.CriticalUnassessed != 2 {
		t.Errorf("critical %d (want 6), unassessed %d (want 2: CVE-OPEN and CVE-SHADOW)", stats.CriticalFindings, stats.CriticalUnassessed)
	}
}
