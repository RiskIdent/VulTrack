package autoassess_test

// R-KMOD end to end: runtime facts, a mapped kernel build and a CVE record
// lead to a decision that records the facts it used, waits for the facts to
// settle, and is revoked as soon as the module is loaded.
//
// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/vultrack/vultrack/internal/kernelintel"
	"github.com/vultrack/vultrack/internal/services"
)

func TestKMODEvaluation(t *testing.T) {
	fx := setup(t)
	ctx, pool := fx.ctx, fx.pool
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	const release = "6.8.0-147-generic"
	exec(`UPDATE servers SET kernel = $1`, release)
	exec(`INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state, severity, source_type, first_seen_at, last_seen_at)
	      VALUES ($1, 'CVE-SCTP', 'kernel', $2, 'affected', 'high', 'oval', NOW(), NOW())`, fx.s1, release)
	exec(`INSERT INTO cve_catalog (cve_id, description, cvss3_score) VALUES ('CVE-SCTP', '', 7.8)`)
	exec(`INSERT INTO server_packages (server_id, name, version, arch, source_package, first_seen_at, last_seen_at)
	      VALUES ($1, 'linux-modules-' || $2, '6.8.0-147.147', 'amd64', 'linux', NOW(), NOW())`, fx.s1, release)
	exec(`INSERT INTO kernel_cve_files (cve_id, status, assigner, program_files, fetched_at)
	      VALUES ('CVE-SCTP', 'ok', 'Linux', ARRAY['net/sctp/socket.c'], NOW())`)
	var buildID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO kernel_builds (release, version, arch, status, headers_package, source_files, modules_verified, shipped_modules, built_at)
		VALUES ($1, '6.8.0-147.147', 'amd64', 'ok', 'linux-headers-6.8.0-147', 1, true, 1, NOW()) RETURNING id`, release).Scan(&buildID); err != nil {
		t.Fatal(err)
	}
	targets, _ := json.Marshal([]kernelintel.Target{{Kind: kernelintel.KindModule, Module: "kernel/net/sctp/sctp.ko", Config: "CONFIG_IP_SCTP", Shipped: true}})
	exec(`INSERT INTO kernel_source_files (build_id, path, targets) VALUES ($1, 'net/sctp/socket.c', $2)`, buildID, targets)

	// Facts as the agent reports them: sctp is installed and blocked.
	facts := services.NewRuntimeFactsService(pool)
	available := []string{"kernel/net/sctp/sctp.ko.zst"}
	report := func(loaded []map[string]string, withIndex bool) {
		t.Helper()
		idx := map[string]any{"hash": services.ModuleIndexHash(release, available, []string{})}
		if withIndex {
			idx["available"], idx["builtin"] = available, []string{}
		}
		raw, _ := json.Marshal(map[string]any{"schemaVersion": 1, "kernel": map[string]any{
			"release": release, "modulesDisabled": false, "loadedModules": loaded,
			"blacklistedModules": []map[string]string{{"name": "sctp", "installCommand": "/bin/true"}},
			"moduleIndex":        idx,
		}})
		if _, err := facts.Ingest(ctx, fx.s1, raw); err != nil {
			t.Fatal(err)
		}
	}
	report([]map[string]string{{"name": "ext4", "path": "kernel/fs/ext4/ext4.ko.zst"}}, true)

	decision := func() (bool, string, map[string]string) {
		t.Helper()
		var reason string
		var ev struct {
			Facts map[string]string `json:"facts"`
		}
		err := pool.QueryRow(ctx, `SELECT reason, evidence FROM auto_decisions WHERE server_id = $1 AND cve_id = 'CVE-SCTP'`, fx.s1).Scan(&reason, &ev)
		if err == pgx.ErrNoRows {
			return false, "", nil
		}
		if err != nil {
			t.Fatal(err)
		}
		return true, reason, ev.Facts
	}

	// Fresh facts: the decision waits for them to settle.
	fx.evaluateAll(t)
	if ok, _, _ := decision(); ok {
		t.Fatal("decision created before the facts settled")
	}
	exec(`UPDATE server_facts SET stable_since = NOW() - interval '3 hours' WHERE server_id = $1`, fx.s1)
	fx.evaluateAll(t)
	ok, reason, evFacts := decision()
	if !ok {
		t.Fatal("no R-KMOD decision once the facts settled")
	}
	var kernelHash string
	if err := pool.QueryRow(ctx, `SELECT hash FROM server_facts WHERE server_id = $1 AND category = 'kernel'`, fx.s1).Scan(&kernelHash); err != nil {
		t.Fatal(err)
	}
	if evFacts["kernel"] != kernelHash {
		t.Errorf("evidence facts %v, want kernel=%s", evFacts, kernelHash)
	}
	t.Logf("reason: %s", reason)

	// Unchanged report: nothing changes; the snapshot GC keeps the referenced snapshot.
	report([]map[string]string{{"name": "ext4", "path": "kernel/fs/ext4/ext4.ko.zst"}}, false)
	if r := fx.evaluateAll(t); r.Created+r.Changed+r.Revoked != 0 {
		t.Errorf("unchanged facts changed decisions: %+v", r)
	}

	// The module gets loaded: revoked at once, without waiting.
	report([]map[string]string{{"name": "ext4", "path": "kernel/fs/ext4/ext4.ko.zst"}, {"name": "sctp", "path": "kernel/net/sctp/sctp.ko.zst"}}, false)
	if r := fx.evaluateAll(t); r.Revoked != 1 {
		t.Errorf("loading the module must revoke the decision: %+v", r)
	}
	if ok, _, _ := decision(); ok {
		t.Error("decision still stored")
	}

	// Unloaded again: a fresh change, so it waits again.
	report([]map[string]string{{"name": "ext4", "path": "kernel/fs/ext4/ext4.ko.zst"}}, false)
	fx.evaluateAll(t)
	if ok, _, _ := decision(); ok {
		t.Error("a decision right after the facts changed")
	}

	// Settle window 0: immediate.
	fx.set(t, map[string]string{services.SettingAutoFactSettle: "0"})
	fx.evaluateAll(t)
	if ok, _, _ := decision(); !ok {
		t.Error("with settle window 0 the decision is immediate")
	}

	// A different running kernel than the scanned one: revoked.
	exec(`UPDATE servers SET kernel = '6.8.0-150-generic' WHERE id = $1`, fx.s1)
	if r := fx.evaluateAll(t); r.Revoked != 1 {
		t.Errorf("kernel mismatch must revoke: %+v", r)
	}
}
