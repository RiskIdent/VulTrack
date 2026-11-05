package autoassess_test

// End to end: the evaluator stores decisions, the triage queue honours them
// per mode, humans override them, and the audit trail records every change.
//
// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/autoassess"
	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

type fixture struct {
	pool     *pgxpool.Pool
	ctx      context.Context
	settings *services.SettingsService
	findings *services.FindingService
	auto     *services.AutoAssessmentService
	eval     *autoassess.Evaluator
	s1, s2   int64
}

func setup(t *testing.T) *fixture {
	pool, ctx := testdb.Setup(t, "autoassess_tests")
	fx := &fixture{pool: pool, ctx: ctx,
		settings: services.NewSettingsService(pool), findings: services.NewFindingService(pool),
		auto: services.NewAutoAssessmentService(pool)}
	fx.eval = autoassess.New(pool, fx.settings)
	for i, name := range []string{"srv-a", "srv-b"} {
		var id int64
		if err := pool.QueryRow(ctx, `
			INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager)
			VALUES ($1, 'ubuntu', '24.04', 'noble', '6.8.0', 'amd64', 'dpkg') RETURNING id`, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			fx.s1 = id
		} else {
			fx.s2 = id
		}
	}
	add := func(server int64, cve, pkg, vex string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state, severity, source_type,
			                      vex_status, first_seen_at, last_seen_at)
			VALUES ($1, $2, $3, '1.0', 'affected', 'high', 'usn', NULLIF($4, ''), NOW(), NOW())`, server, cve, pkg, vex); err != nil {
			t.Fatal(err)
		}
	}
	add(fx.s1, "CVE-A", "linux-libc-dev", "") // headers on both servers
	add(fx.s2, "CVE-A", "linux-libc-dev", "")
	add(fx.s1, "CVE-B", "libfoo1", "") // nothing dismisses it
	add(fx.s2, "CVE-B", "libfoo1", "")
	add(fx.s1, "CVE-C", "bar", "not_affected") // VEX, one server
	add(fx.s1, "CVE-K", "linux-libc-dev", "")  // KEV-listed
	for _, cve := range []string{"CVE-A", "CVE-B", "CVE-C", "CVE-K"} {
		if _, err := pool.Exec(ctx, `INSERT INTO cve_catalog (cve_id, description, cvss3_score) VALUES ($1, '', 8.0)`, cve); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO kev_entries (cve_id, vendor_project) VALUES ('CVE-K', 'v')`); err != nil {
		t.Fatal(err)
	}
	return fx
}

func (fx *fixture) evaluateAll(t *testing.T) autoassess.Result {
	t.Helper()
	var total autoassess.Result
	for _, id := range []int64{fx.s1, fx.s2} {
		r, err := fx.eval.EvaluateServer(fx.ctx, id)
		if err != nil {
			t.Fatalf("EvaluateServer: %v", err)
		}
		total.Created += r.Created
		total.Changed += r.Changed
		total.Revoked += r.Revoked
	}
	return total
}

func (fx *fixture) set(t *testing.T, kv map[string]string) {
	t.Helper()
	if err := fx.settings.SetMultiple(fx.ctx, kv); err != nil {
		t.Fatal(err)
	}
}

// queue returns the CVEs in the triage queue, as the UI and MCP build it.
func (fx *fixture) queue(t *testing.T) string {
	t.Helper()
	opts, err := fx.settings.BuildTriageOptions(fx.ctx)
	if err != nil {
		t.Fatal(err)
	}
	opts.Mode, opts.CVSSThreshold, opts.HideVexNotAffected, opts.HideVendorAccepted, opts.Limit = "cvss", 7, false, false, 50
	findings, total, err := fx.findings.GetTriageQueue(fx.ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.CVEID)
	}
	sort.Strings(ids)
	if total != len(ids) {
		t.Errorf("queue total %d but %d CVEs returned", total, len(ids))
	}
	return strings.Join(ids, ",")
}

func (fx *fixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := fx.pool.QueryRow(fx.ctx, query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestEvaluator(t *testing.T) {
	fx := setup(t)

	if r := fx.evaluateAll(t); r.Created != 4 || r.Changed != 0 || r.Revoked != 0 {
		t.Fatalf("first run = %+v, want 4 created (A on both servers, C, K)", r)
	}
	if n := fx.count(t, `SELECT COUNT(*) FROM decision_events WHERE event = 'auto_created'`); n != 4 {
		t.Errorf("auto_created events = %d", n)
	}
	if n := fx.count(t, `SELECT COUNT(*) FROM auto_decisions WHERE cve_id = 'CVE-K' AND guards = '{G-KEV}'`); n != 1 {
		t.Error("CVE-K must be stored as blocked by G-KEV")
	}

	t.Run("an unchanged re-evaluation writes nothing", func(t *testing.T) {
		before := fx.count(t, `SELECT COUNT(*) FROM decision_events`)
		if r := fx.evaluateAll(t); r != (autoassess.Result{}) {
			t.Errorf("second run = %+v", r)
		}
		if after := fx.count(t, `SELECT COUNT(*) FROM decision_events`); after != before {
			t.Errorf("events %d -> %d", before, after)
		}
	})

	t.Run("shadow mode leaves the queue unchanged", func(t *testing.T) {
		if q := fx.queue(t); q != "CVE-A,CVE-B,CVE-C,CVE-K" {
			t.Errorf("queue = %s", q)
		}
	})

	t.Run("active rule removes its decisions from the queue", func(t *testing.T) {
		fx.set(t, map[string]string{"auto_assessment_mode": "active", "auto_assessment_rule_modes": `{"R-HDR":"active"}`})
		// CVE-A dismissed on both servers; CVE-K blocked by KEV; CVE-C's rule still in shadow.
		if q := fx.queue(t); q != "CVE-B,CVE-C,CVE-K" {
			t.Errorf("queue = %s", q)
		}
		fx.set(t, map[string]string{"auto_assessment_rule_modes": `{"R-HDR":"active","R-VEX":"active"}`})
		if q := fx.queue(t); q != "CVE-B,CVE-K" {
			t.Errorf("queue = %s", q)
		}
	})

	t.Run("dashboard count follows the queue", func(t *testing.T) {
		opts, _ := fx.settings.BuildTriageOptions(fx.ctx)
		opts.Mode, opts.CVSSThreshold, opts.HideVexNotAffected, opts.HideVendorAccepted = "cvss", 7, false, false
		if n, err := fx.findings.CountTriageQueue(fx.ctx, opts); err != nil || n != 2 {
			t.Errorf("count = %d, err %v", n, err)
		}
	})

	t.Run("manual override brings a server back; a human decision removes it", func(t *testing.T) {
		if _, err := fx.auto.SetOverride(fx.ctx, fx.s1, "CVE-A", "manual", "check by hand", "alice"); err != nil {
			t.Fatal(err)
		}
		if q := fx.queue(t); q != "CVE-A,CVE-B,CVE-K" {
			t.Errorf("queue with manual override = %s", q)
		}
		if _, err := fx.auto.SetOverride(fx.ctx, fx.s1, "CVE-A", "relevant", "needs patching", "alice"); err != nil {
			t.Fatal(err)
		}
		if q := fx.queue(t); q != "CVE-B,CVE-K" {
			t.Errorf("queue with human decision = %s", q)
		}
		cfg, _ := fx.settings.LoadAutoAssessmentConfig(fx.ctx)
		st, err := fx.auto.CVEServerStatuses(fx.ctx, cfg, "CVE-A")
		if err != nil || len(st) != 2 {
			t.Fatalf("statuses = %+v, err %v", st, err)
		}
		if st[0].ServerName != "srv-a" || st[0].Status != "relevant" || st[0].Source != "override" || st[0].Decision.State != services.DecisionOverridden {
			t.Errorf("srv-a = %+v / %+v", st[0], st[0].Decision)
		}
		if st[1].Status != "not_relevant" || st[1].Source != "auto" || st[1].Decision.State != services.DecisionApplied {
			t.Errorf("srv-b = %+v", st[1])
		}
		excluded, err := fx.auto.ExcludedFromTicket(fx.ctx, cfg, "CVE-A", false)
		if err != nil || len(excluded) != 1 || !strings.Contains(excluded[fx.s2], "R-HDR") {
			t.Errorf("excluded = %v, err %v", excluded, err)
		}
		if ex, _ := fx.auto.ExcludedFromTicket(fx.ctx, cfg, "CVE-A", true); len(ex) != 0 {
			t.Errorf("a binding assessment covers every server: %v", ex)
		}
		if removed, err := fx.auto.RemoveOverride(fx.ctx, fx.s1, "CVE-A", "alice"); err != nil || !removed {
			t.Fatalf("RemoveOverride = %v, %v", removed, err)
		}
		if n := fx.count(t, `SELECT COUNT(*) FROM decision_events WHERE actor = 'alice'`); n != 3 {
			t.Errorf("human events = %d, want 3 (two sets, one removal)", n)
		}
	})

	t.Run("binding assessment overrides automation", func(t *testing.T) {
		if _, err := fx.pool.Exec(fx.ctx, `INSERT INTO assessments (cve_id, status, binding_all_servers) VALUES ('CVE-A', 'relevant', true)`); err != nil {
			t.Fatal(err)
		}
		cfg, _ := fx.settings.LoadAutoAssessmentConfig(fx.ctx)
		st, _ := fx.auto.CVEServerStatuses(fx.ctx, cfg, "CVE-A")
		for _, s := range st {
			if s.Status != "relevant" || s.Source != "binding" || s.Decision.State != services.DecisionOverridden {
				t.Errorf("%s = %s/%s/%s", s.ServerName, s.Status, s.Source, s.Decision.State)
			}
		}
	})

	t.Run("stats count per rule and agreement with humans", func(t *testing.T) {
		cfg, _ := fx.settings.LoadAutoAssessmentConfig(fx.ctx)
		st, err := fx.auto.Stats(fx.ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		byRule := map[string]services.RuleStats{}
		for _, r := range st.Rules {
			byRule[r.RuleID] = r
		}
		hdr := byRule["R-HDR"]
		// R-HDR: CVE-A on both servers (overridden by the binding assessment, human disagrees)
		// and CVE-K (blocked).
		if hdr.Decisions != 3 || hdr.Overridden != 2 || hdr.Blocked != 1 || hdr.HumanDisagree != 2 || hdr.HumanAgree != 0 {
			t.Errorf("R-HDR = %+v", hdr)
		}
		if vex := byRule["R-VEX"]; vex.Decisions != 1 || vex.Applied != 1 {
			t.Errorf("R-VEX = %+v", vex)
		}
		if st.Guards["G-KEV"] != 1 || st.Total.Decisions != 4 {
			t.Errorf("guards %v, total %+v", st.Guards, st.Total)
		}
		// Pairs: A×2, B×2, C, K = 6; decided: A×2 (binding), C (applied) → open 3.
		if st.TotalPairs != 6 || st.OpenPairs != 3 {
			t.Errorf("pairs total %d open %d", st.TotalPairs, st.OpenPairs)
		}
		if len(st.Activity) != 30 || st.Activity[29].Created != 4 {
			t.Errorf("activity today = %+v", st.Activity[len(st.Activity)-1])
		}
	})

	t.Run("list decisions by state and rule", func(t *testing.T) {
		cfg, _ := fx.settings.LoadAutoAssessmentConfig(fx.ctx)
		blocked, n, err := fx.auto.ListDecisions(fx.ctx, cfg, services.DecisionFilter{State: services.DecisionBlocked})
		if err != nil || n != 1 || blocked[0].CVEID != "CVE-K" {
			t.Errorf("blocked = %+v (%d), err %v", blocked, n, err)
		}
		vex, n, err := fx.auto.ListDecisions(fx.ctx, cfg, services.DecisionFilter{RuleID: "R-VEX", Search: "srv-a"})
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 || vex[0].State != services.DecisionApplied || !strings.Contains(string(vex[0].Evidence), "R-VEX") {
			t.Errorf("R-VEX = %+v", vex)
		}
	})

	t.Run("a new unmatched finding revokes the decision", func(t *testing.T) {
		if _, err := fx.pool.Exec(fx.ctx, `
			INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state, severity, source_type, first_seen_at, last_seen_at)
			VALUES ($1, 'CVE-C', 'baz', '1.0', 'affected', 'high', 'usn', NOW(), NOW())`, fx.s1); err != nil {
			t.Fatal(err)
		}
		if r := fx.evaluateAll(t); r.Revoked != 1 {
			t.Errorf("result = %+v", r)
		}
		if n := fx.count(t, `SELECT COUNT(*) FROM decision_events WHERE event = 'auto_revoked' AND cve_id = 'CVE-C'`); n != 1 {
			t.Error("revocation not recorded")
		}
	})

	t.Run("a guard change rewrites the decision", func(t *testing.T) {
		if _, err := fx.pool.Exec(fx.ctx, `DELETE FROM kev_entries`); err != nil {
			t.Fatal(err)
		}
		if r := fx.evaluateAll(t); r.Changed != 1 {
			t.Errorf("result = %+v, want CVE-K changed", r)
		}
	})

	t.Run("a rule switched off loses its decisions", func(t *testing.T) {
		fx.set(t, map[string]string{"auto_assessment_rule_modes": `{"R-HDR":"off","R-VEX":"active"}`})
		if r := fx.evaluateAll(t); r.Revoked != 3 {
			t.Errorf("result = %+v, want the three R-HDR decisions revoked", r)
		}
	})

	t.Run("mode off evaluates nothing and restores the queue", func(t *testing.T) {
		fx.set(t, map[string]string{"auto_assessment_mode": "off", "auto_assessment_rule_modes": `{"R-HDR":"active"}`})
		if r := fx.evaluateAll(t); r != (autoassess.Result{}) {
			t.Errorf("result = %+v", r)
		}
		// CVE-A is assessed (binding); everything else is in the queue as before.
		if q := fx.queue(t); q != "CVE-B,CVE-C,CVE-K" {
			t.Errorf("queue = %s", q)
		}
	})
}
