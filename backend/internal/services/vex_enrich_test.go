package services_test

// EnrichFindings used to start from vex_statements: a sequential scan of the
// whole table (90 million rows across every Ubuntu release) and a sort of the
// distro's statements, on every scan of every server. It now starts from the
// server's findings and looks each one up through the index. These tests pin
// its result to that of the original statement, and check that a rescan leaves
// unchanged findings alone.
//
// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

// legacyEnrichQuery is the statement EnrichFindings ran before it was rewritten,
// kept as the reference for its result.
const legacyEnrichQuery = `
	UPDATE findings f
	SET
		vex_status        = v.status,
		vex_justification = v.justification,
		fix_state         = CASE
			WHEN v.status = 'will_not_fix' AND f.fix_state = 'affected' THEN 'will_not_fix'
			ELSE f.fix_state
		END,
		updated_at        = NOW()
	FROM (
		SELECT DISTINCT ON (cve_id, package_name)
			cve_id, package_name, status, justification
		FROM vex_statements
		WHERE distro = $2
		  AND status != 'fixed'
		ORDER BY cve_id, package_name,
			CASE status
				WHEN 'not_affected'        THEN 0
				WHEN 'under_investigation' THEN 1
				WHEN 'will_not_fix'        THEN 2
				ELSE 3
			END
	) v
	WHERE f.server_id  = $1
	  AND f.resolved_at IS NULL
	  AND f.cve_id       = v.cve_id
	  AND f.package_name = v.package_name`

type vexState struct {
	VexStatus, VexJustification, FixState string
}

// readVexStates returns the VEX-related columns of every finding, keyed by
// "server|cve|package".
func readVexStates(t *testing.T, ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}) map[string]vexState {
	t.Helper()
	rows, err := q.Query(ctx, `
		SELECT s.name || '|' || f.cve_id || '|' || f.package_name,
		       COALESCE(f.vex_status, ''), COALESCE(f.vex_justification, ''), COALESCE(f.fix_state, '')
		FROM findings f JOIN servers s ON s.id = f.server_id
	`)
	if err != nil {
		t.Fatalf("read findings: %v", err)
	}
	defer rows.Close()
	states := map[string]vexState{}
	for rows.Next() {
		var key string
		var st vexState
		if err := rows.Scan(&key, &st.VexStatus, &st.VexJustification, &st.FixState); err != nil {
			t.Fatalf("scan finding: %v", err)
		}
		states[key] = st
	}
	return states
}

func seedVexEnrichment(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (target, other int64) {
	t.Helper()

	insertServer := func(name string) int64 {
		var id int64
		err := pool.QueryRow(ctx, `
			INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager)
			VALUES ($1, 'ubuntu', '24.04', 'noble', '6.8.0-124-generic', 'amd64', 'dpkg')
			RETURNING id
		`, name).Scan(&id)
		if err != nil {
			t.Fatalf("insert server %s: %v", name, err)
		}
		return id
	}
	target, other = insertServer("target"), insertServer("other")

	findings := []struct {
		server        int64
		cve, pkg, fix string
		resolved      bool
	}{
		{target, "CVE-2026-1001", "pkg-a", "affected", false},      // not_affected beats will_not_fix
		{target, "CVE-2026-1002", "pkg-b", "affected", false},      // will_not_fix overrides affected
		{target, "CVE-2026-1003", "pkg-c", "fix_available", false}, // will_not_fix never overrides a fix
		{target, "CVE-2026-1004", "pkg-d", "affected", false},      // only a 'fixed' statement
		{target, "CVE-2026-1005", "pkg-e", "affected", false},      // statement for another release only
		{target, "CVE-2026-1006", "pkg-f", "affected", true},       // resolved
		{target, "CVE-2026-1007", "pkg-g", "affected", false},      // under_investigation beats will_not_fix
		{other, "CVE-2026-1001", "pkg-a", "affected", false},       // another server
	}
	for _, f := range findings {
		_, err := pool.Exec(ctx, `
			INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state,
			                      severity, source_type, first_seen_at, last_seen_at, resolved_at)
			VALUES ($1, $2, $3, '1.0', $4, 'high', 'usn', NOW(), NOW(),
			        CASE WHEN $5::bool THEN NOW() END)
		`, f.server, f.cve, f.pkg, f.fix, f.resolved)
		if err != nil {
			t.Fatalf("insert finding %s/%s: %v", f.cve, f.pkg, err)
		}
	}

	statements := []struct{ cve, pkg, distro, status, justification, sourceType string }{
		{"CVE-2026-1001", "pkg-a", "noble", "will_not_fix", "ignored", "cve"},
		{"CVE-2026-1001", "pkg-a", "noble", "not_affected", "code not present", "usn"},
		{"CVE-2026-1002", "pkg-b", "noble", "will_not_fix", "ignored", "cve"},
		{"CVE-2026-1003", "pkg-c", "noble", "will_not_fix", "ignored", "cve"},
		{"CVE-2026-1004", "pkg-d", "noble", "fixed", "", "cve"},
		{"CVE-2026-1005", "pkg-e", "jammy", "not_affected", "jammy only", "cve"},
		{"CVE-2026-1006", "pkg-f", "noble", "not_affected", "resolved anyway", "cve"},
		{"CVE-2026-1007", "pkg-g", "noble", "will_not_fix", "ignored", "cve"},
		{"CVE-2026-1007", "pkg-g", "noble", "under_investigation", "triage pending", "usn"},
	}
	for _, s := range statements {
		_, err := pool.Exec(ctx, `
			INSERT INTO vex_statements (cve_id, package_name, distro, status, justification, source_type, source_id)
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7)
		`, s.cve, s.pkg, s.distro, s.status, s.justification, s.sourceType, s.cve)
		if err != nil {
			t.Fatalf("insert vex statement %s/%s: %v", s.cve, s.pkg, err)
		}
	}
	return target, other
}

func TestEnrichFindings(t *testing.T) {
	pool, ctx := testdb.Setup(t, "vex_enrich_tests")
	target, _ := seedVexEnrichment(t, ctx, pool)
	vexService := services.NewVEXService(pool)

	// What the original statement produces, computed in a transaction that is
	// rolled back so the rewritten one starts from the same data.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(ctx, legacyEnrichQuery, target, "noble"); err != nil {
		t.Fatalf("legacy enrichment: %v", err)
	}
	want := readVexStates(t, ctx, tx)
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	changed, err := vexService.EnrichFindings(ctx, target, "noble")
	if err != nil {
		t.Fatalf("EnrichFindings: %v", err)
	}
	if changed != 4 {
		t.Errorf("first run changed %d findings, want 4", changed)
	}

	got := readVexStates(t, ctx, pool)
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d", len(got), len(want))
	}
	for key, w := range want {
		if got[key] != w {
			t.Errorf("%s = %+v, the original statement gives %+v", key, got[key], w)
		}
	}

	// Spot-check the rules themselves, so the test does not only prove that two
	// statements agree.
	expect := map[string]vexState{
		"target|CVE-2026-1001|pkg-a": {"not_affected", "code not present", "affected"},
		"target|CVE-2026-1002|pkg-b": {"will_not_fix", "ignored", "will_not_fix"},
		"target|CVE-2026-1003|pkg-c": {"will_not_fix", "ignored", "fix_available"},
		"target|CVE-2026-1004|pkg-d": {"", "", "affected"},
		"target|CVE-2026-1005|pkg-e": {"", "", "affected"},
		"target|CVE-2026-1006|pkg-f": {"", "", "affected"},
		"target|CVE-2026-1007|pkg-g": {"under_investigation", "triage pending", "affected"},
		"other|CVE-2026-1001|pkg-a":  {"", "", "affected"},
	}
	for key, e := range expect {
		if got[key] != e {
			t.Errorf("%s = %+v, want %+v", key, got[key], e)
		}
	}

	t.Run("rescan without changes writes nothing", func(t *testing.T) {
		changed, err := vexService.EnrichFindings(ctx, target, "noble")
		if err != nil {
			t.Fatalf("EnrichFindings: %v", err)
		}
		if changed != 0 {
			t.Errorf("rescan changed %d findings, want 0", changed)
		}
	})

	// The scan's upsert writes OVAL's fix_state back on every run, so the
	// will_not_fix override has to be reapplied even though the VEX columns
	// already match.
	t.Run("rescan reapplies will_not_fix after the upsert", func(t *testing.T) {
		_, err := pool.Exec(ctx, `
			UPDATE findings SET fix_state = 'affected' WHERE cve_id = 'CVE-2026-1002' AND server_id = $1
		`, target)
		if err != nil {
			t.Fatalf("reset fix_state: %v", err)
		}
		changed, err := vexService.EnrichFindings(ctx, target, "noble")
		if err != nil {
			t.Fatalf("EnrichFindings: %v", err)
		}
		if changed != 1 {
			t.Errorf("rescan changed %d findings, want 1", changed)
		}
		if st := readVexStates(t, ctx, pool)["target|CVE-2026-1002|pkg-b"]; st.FixState != "will_not_fix" {
			t.Errorf("fix_state = %q, want will_not_fix", st.FixState)
		}
	})
}
