package services_test

// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"testing"

	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

// A (server, CVE) group over findings of different severities must report the
// highest one; as text, "medium" and "unknown" sort above "critical".
func TestGroupedSeverityIsTheHighest(t *testing.T) {
	pool, ctx := testdb.Setup(t, "severity_rank_tests")
	var a int64
	pool.QueryRow(ctx, `INSERT INTO servers (name, os_family, os_release) VALUES ('a', 'ubuntu', '24.04') RETURNING id`).Scan(&a)
	for pkg, sev := range map[string]string{"p1": "critical", "p2": "medium", "p3": "unknown"} {
		if _, err := pool.Exec(ctx, `INSERT INTO findings (server_id, cve_id, package_name, severity, cvss3_score, first_seen_at, last_seen_at)
			VALUES ($1, 'CVE-1', $2, $3, 9.0, NOW(), NOW())`, a, pkg, sev); err != nil {
			t.Fatal(err)
		}
	}
	groups, _, err := services.NewFindingService(pool).GetAllGrouped(ctx, services.FindingFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Severity != "critical" {
		t.Errorf("grouped severity %+v, want critical", groups)
	}
	var top string
	if err := pool.QueryRow(ctx, `SELECT severity_from_rank(MAX(severity_rank(severity))) FROM findings`).Scan(&top); err != nil || top != "critical" {
		t.Errorf("severity_from_rank: %q %v", top, err)
	}
}
