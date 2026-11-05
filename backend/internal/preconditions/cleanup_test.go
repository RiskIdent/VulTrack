package preconditions

// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"testing"
	"time"

	"github.com/vultrack/vultrack/internal/database"
	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

func TestCleanupAndMigration(t *testing.T) {
	pool, ctx := testdb.Setup(t, "precondition_cleanup_tests")
	an := New(pool, services.NewSettingsService(pool), services.NewFindingService(pool), nil)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	var srv int64
	if err := pool.QueryRow(ctx, `INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager)
		VALUES ('s', 'ubuntu', '24.04', 'noble', '6.8.0', 'amd64', 'dpkg') RETURNING id`).Scan(&srv); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state, severity, source_type, first_seen_at, last_seen_at)
	      VALUES ($1, 'CVE-ACTIVE', 'p', '1', 'affected', 'high', 'usn', NOW(), NOW())`, srv)
	for _, id := range []string{"CVE-ACTIVE", "CVE-GONE", "CVE-GONE-RECENT"} {
		exec(`INSERT INTO precondition_analyses (cve_id, status, model, prompt_hash, input_hash, analysed_at)
		      VALUES ($1, 'ok', 'm', 'p', 'i', NOW() - interval '100 days')`, id)
	}
	exec(`UPDATE precondition_analyses SET analysed_at = NOW() WHERE cve_id = 'CVE-GONE-RECENT'`)
	exec(`INSERT INTO ai_usage (stage, model, cost_usd, created_at) VALUES ('preconditions', 'm', 1, NOW() - interval '500 days'), ('preconditions', 'm', 1, NOW())`)

	a, _, u, err := an.Cleanup(ctx, 90*24*time.Hour, 400*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if a != 1 || u != 1 {
		t.Errorf("deleted %d analyses, %d usage records; want 1 and 1", a, u)
	}

	// The migration re-opens analyses that failed on a condition without package.
	exec(`INSERT INTO precondition_analyses (cve_id, status, model, prompt_hash, input_hash, error, terminal, requested_at)
	      VALUES ('CVE-NOPKG', 'error', 'm', 'p', 'i', 'model output was invalid: network_listener without package', true, NOW())`)
	exec(`DELETE FROM schema_migrations WHERE name = '2026-11-precondition-empty-package'`)
	if err := database.Migrate(pool); err != nil {
		t.Fatal(err)
	}
	var terminal, recent bool
	if err := pool.QueryRow(ctx, `SELECT terminal, requested_at > NOW() - interval '1 day' FROM precondition_analyses WHERE cve_id = 'CVE-NOPKG'`).
		Scan(&terminal, &recent); err != nil {
		t.Fatal(err)
	}
	if terminal || recent {
		t.Errorf("migration: terminal=%v recent=%v, want both false", terminal, recent)
	}
}
