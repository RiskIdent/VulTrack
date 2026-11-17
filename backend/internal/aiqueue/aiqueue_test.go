package aiqueue

// The refresh check against a throwaway PostgreSQL: completed assessments are
// re-queued when their input facts change or their result gets too old, and
// not because of noise.
//
// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"testing"

	"github.com/vultrack/vultrack/internal/ai"
	"github.com/vultrack/vultrack/internal/config"
	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

func TestRefresh(t *testing.T) {
	pool, ctx := testdb.Setup(t, "aiqueue_tests")
	settings := services.NewSettingsService(pool)
	aiService := services.NewAIAssessmentService(pool)
	q := New(nil, aiService, services.NewFindingService(pool), settings, &config.Config{})

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	var srv int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager)
		VALUES ('web', 'ubuntu', '24.04', 'noble', '6.8.0', 'amd64', 'dpkg') RETURNING id`).Scan(&srv); err != nil {
		t.Fatal(err)
	}
	cves := []string{"CVE-2026-1001", "CVE-2026-1002"}
	for _, cve := range cves {
		exec(`INSERT INTO cve_catalog (cve_id, description, cvss3_score) VALUES ($1, 'overflow', 7.5)`, cve)
		exec(`INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state, severity, source_type, first_seen_at, last_seen_at)
		      VALUES ($1, $2, 'openssl', '3.0.2-1', 'affected', 'high', 'usn', NOW(), NOW())`, srv, cve)
		if _, err := aiService.Enqueue(ctx, cve, "", false); err != nil {
			t.Fatal(err)
		}
		in, err := aiService.BuildInput(ctx, cve)
		if err != nil {
			t.Fatal(err)
		}
		if err := aiService.SaveResult(ctx, cve, ai.AssessmentResult{RecommendedStatus: "relevant"}, ai.AssessmentMeta{}, ai.FactsOf(in)); err != nil {
			t.Fatal(err)
		}
	}
	refresh := func() int {
		t.Helper()
		n, err := q.refresh(ctx, cves)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	reason := func(cve string) (string, string) {
		var status, r string
		pool.QueryRow(ctx, `SELECT status, COALESCE(refresh_reason, '') FROM ai_assessments WHERE cve_id = $1`, cve).Scan(&status, &r)
		return status, r
	}
	// complete simulates the worker: a fresh result on the current facts.
	complete := func(cve string) {
		t.Helper()
		in, err := aiService.BuildInput(ctx, cve)
		if err != nil {
			t.Fatal(err)
		}
		if err := aiService.SaveResult(ctx, cve, ai.AssessmentResult{RecommendedStatus: "relevant"}, ai.AssessmentMeta{}, ai.FactsOf(in)); err != nil {
			t.Fatal(err)
		}
	}

	// Unchanged, or only noise (a new package version, EPSS within its band).
	exec(`UPDATE findings SET package_version = '3.0.2-2'`)
	exec(`INSERT INTO epss_scores (cve_id, epss, percentile, score_date) VALUES ('CVE-2026-1001', 0, 0.1, CURRENT_DATE)`)
	if n := refresh(); n != 0 {
		t.Fatalf("noise re-queued %d", n)
	}

	// Listed in KEV and a fix becomes available: re-queued with the reason,
	// the previous result kept.
	exec(`INSERT INTO kev_entries (cve_id, date_added) VALUES ('CVE-2026-1001', '2026-11-10')`)
	exec(`UPDATE findings SET fix_state = 'fix_available' WHERE cve_id = 'CVE-2026-1001'`)
	if n := refresh(); n != 1 {
		t.Fatalf("re-queued %d, want 1", n)
	}
	if st, r := reason("CVE-2026-1001"); st != "pending" || r != "CISA KEV: no → yes; fix available: no → yes" {
		t.Errorf("status %s, reason %q", st, r)
	}
	var kept string
	pool.QueryRow(ctx, `SELECT recommended_status FROM ai_assessments WHERE cve_id = 'CVE-2026-1001'`).Scan(&kept)
	if kept != "relevant" {
		t.Error("the previous result was cleared")
	}
	// Pending rows are not touched again.
	if n := refresh(); n != 0 {
		t.Errorf("pending row re-queued again: %d", n)
	}
	complete("CVE-2026-1001")

	// Results stored before facts were recorded.
	exec(`UPDATE ai_assessments SET input_facts = NULL WHERE cve_id = 'CVE-2026-1002'`)
	if n := refresh(); n != 1 {
		t.Fatalf("legacy re-queued %d, want 1", n)
	}
	complete("CVE-2026-1002")

	// Age: off with 0, due after the configured days.
	exec(`UPDATE ai_assessments SET assessed_at = NOW() - interval '100 days' WHERE cve_id = 'CVE-2026-1002'`)
	exec(`INSERT INTO settings (key, value) VALUES ($1, '0')`, services.SettingAIMaxAgeDays)
	if n := refresh(); n != 0 {
		t.Errorf("max age 0 re-queued %d", n)
	}
	exec(`UPDATE settings SET value = '90' WHERE key = $1`, services.SettingAIMaxAgeDays)
	if n := refresh(); n != 1 {
		t.Fatalf("old result re-queued %d, want 1", n)
	}
	if _, r := reason("CVE-2026-1002"); r != "result older than 90 days" {
		t.Errorf("reason %q", r)
	}

	// A manual re-run clears the automatic reason.
	exec(`UPDATE ai_assessments SET status = 'completed', updated_at = NOW() - interval '1 hour'`)
	if out, err := aiService.Enqueue(ctx, "CVE-2026-1002", "kai", true); err != nil || out != services.EnqueueRequeued {
		t.Fatalf("manual re-run: %v %v", out, err)
	}
	if _, r := reason("CVE-2026-1002"); r != "" {
		t.Errorf("manual re-run kept reason %q", r)
	}
}
