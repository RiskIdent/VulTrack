package autoassess_test

// R-UNUSED end to end: agent reports build the usage observation, packageInfo
// drives the rule, and use of the package revokes the decision.
//
// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"encoding/json"
	"testing"

	"github.com/vultrack/vultrack/internal/services"
)

func TestUnusedEvaluation(t *testing.T) {
	fx := setup(t)
	ctx, pool := fx.ctx, fx.pool
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state, severity, source_type, first_seen_at, last_seen_at)
	      VALUES ($1, 'CVE-OLD', 'libold1', '1.0', 'affected', 'high', 'usn', NOW(), NOW())`, fx.s1)
	exec(`INSERT INTO cve_catalog (cve_id, description, cvss3_score) VALUES ('CVE-OLD', '', 7.5)`)

	facts := services.NewRuntimeFactsService(pool)
	report := func(inUse ...string) {
		t.Helper()
		entries := []map[string]any{}
		for _, p := range inUse {
			entries = append(entries, map[string]any{"package": p, "processes": []string{"x"}})
		}
		raw, _ := json.Marshal(map[string]any{"schemaVersion": 1,
			"packagesInUse": entries,
			"packageInfo": []map[string]any{
				{"package": "curl", "entryPoints": []string{"executable"}, "depends": []string{"libc6"}},
				{"package": "libc6"},
				{"package": "libold1", "depends": []string{"libc6"}},
			},
			"truncated": []string{"packagesInUse"}, // process lists cut: must not matter
		})
		if _, err := facts.Ingest(ctx, fx.s1, raw); err != nil {
			t.Fatal(err)
		}
	}
	decided := func() bool {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM auto_decisions WHERE server_id = $1 AND cve_id = 'CVE-OLD'`, fx.s1).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}

	report("libc6")
	fx.evaluateAll(t)
	if decided() {
		t.Fatal("decided before the observation period")
	}

	// 15 days of gap-free observation, packageInfo settled.
	exec(`UPDATE package_usage_observation SET observed_since = NOW() - interval '15 days'`)
	exec(`UPDATE server_facts SET stable_since = NOW() - interval '1 day' WHERE server_id = $1`, fx.s1)
	report("libc6")
	fx.evaluateAll(t)
	if !decided() {
		t.Fatal("no R-UNUSED decision after 15 unused days")
	}

	// A process maps the library: revoked at once.
	report("libc6", "libold1")
	if r := fx.evaluateAll(t); r.Revoked != 1 || decided() {
		t.Errorf("use of the package must revoke the decision: %+v", r)
	}

	// Unused again: it was in use less than 14 days ago, so it stays open.
	report("libc6")
	fx.evaluateAll(t)
	if decided() {
		t.Error("decided although in use within the period")
	}
}
