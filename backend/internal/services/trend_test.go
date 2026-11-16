package services_test

// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"testing"

	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

func TestFindingsTrendTotal(t *testing.T) {
	pool, ctx := testdb.Setup(t, "trend_tests")
	var srv int64
	if err := pool.QueryRow(ctx, `INSERT INTO servers (name, os_family, os_release) VALUES ('s', 'ubuntu', '24.04') RETURNING id`).Scan(&srv); err != nil {
		t.Fatal(err)
	}
	// 3 days ago: 2 new; yesterday: 1 new, 1 of the first resolved; today: 1 new.
	for _, q := range []string{
		`INSERT INTO findings (server_id, cve_id, package_name, first_seen_at, last_seen_at, resolved_at) VALUES ($1, 'CVE-1', 'p', CURRENT_DATE - 3, NOW(), CURRENT_DATE - 1)`,
		`INSERT INTO findings (server_id, cve_id, package_name, first_seen_at, last_seen_at) VALUES ($1, 'CVE-2', 'p', CURRENT_DATE - 3, NOW())`,
		`INSERT INTO findings (server_id, cve_id, package_name, first_seen_at, last_seen_at) VALUES ($1, 'CVE-3', 'p', CURRENT_DATE - 1, NOW())`,
		`INSERT INTO findings (server_id, cve_id, package_name, first_seen_at, last_seen_at) VALUES ($1, 'CVE-4', 'p', CURRENT_DATE, NOW())`,
	} {
		if _, err := pool.Exec(ctx, q, srv); err != nil {
			t.Fatal(err)
		}
	}
	trend, err := services.NewStatsService(pool).GetFindingsTrend(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	var totals []int
	for _, p := range trend {
		totals = append(totals, p.TotalFindings)
	}
	// days -4 .. 0: 0, 2, 2, 2 (one resolved, one new), 3
	want := []int{0, 2, 2, 2, 3}
	if len(totals) != len(want) {
		t.Fatalf("totals %v", totals)
	}
	for i := range want {
		if totals[i] != want[i] {
			t.Fatalf("totals %v, want %v", totals, want)
		}
	}
}
