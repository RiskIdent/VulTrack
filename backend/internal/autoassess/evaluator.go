package autoassess

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/metrics"
	"github.com/vultrack/vultrack/internal/services"
)

// Evaluator computes and stores the automated decisions.
type Evaluator struct {
	db       *pgxpool.Pool
	settings *services.SettingsService

	// allMu serialises full re-evaluations; triggers that arrive while one runs
	// are coalesced into one more run.
	allMu      sync.Mutex
	allPending []string // triggers that arrived while a run was in progress
	allRunning bool

	modIndex moduleIndexCache
}

// New creates an Evaluator.
func New(db *pgxpool.Pool, settings *services.SettingsService) *Evaluator {
	return &Evaluator{db: db, settings: settings}
}

// Result counts what one evaluation changed.
type Result struct {
	Created, Changed, Revoked int
}

func (r *Result) add(o Result) {
	r.Created += o.Created
	r.Changed += o.Changed
	r.Revoked += o.Revoked
}

// enabledRules returns the rules that are not switched off, in catalogue order.
func enabledRules(cfg services.AutoAssessmentConfig) []Rule {
	var out []Rule
	for _, r := range Rules {
		if cfg.RuleMode(r.ID()) != services.AutoModeOff {
			out = append(out, r)
		}
	}
	return out
}

// EvaluateServer re-evaluates every decision of one server and stores what
// changed. With the global mode off it does nothing; stored decisions are then
// ignored by every reader.
func (e *Evaluator) EvaluateServer(ctx context.Context, serverID int64) (Result, error) {
	cfg, err := e.settings.LoadAutoAssessmentConfig(ctx)
	if err != nil {
		return Result{}, err
	}
	if cfg.Mode == services.AutoModeOff {
		return Result{}, nil
	}
	return e.evaluateServer(ctx, serverID, cfg)
}

func (e *Evaluator) evaluateServer(ctx context.Context, serverID int64, cfg services.AutoAssessmentConfig) (Result, error) {
	tx, err := e.db.Begin(ctx)
	if err != nil {
		return Result{}, err
	}
	defer tx.Rollback(ctx)

	// One evaluation per server at a time (scan-triggered and global runs may
	// overlap); the lock is released with the transaction.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('auto_assessment'), $1::int)`, serverID); err != nil {
		return Result{}, err
	}

	findings, err := loadFindings(ctx, tx, serverID)
	if err != nil {
		return Result{}, err
	}
	rules := enabledRules(cfg)
	host, err := e.loadHost(ctx, tx, serverID, findings, rules, time.Duration(cfg.UnusedDays)*24*time.Hour)
	if err != nil {
		return Result{}, err
	}

	// Rules first, then guard data only for the CVEs a rule would dismiss.
	candidates := Decide(findings, host, rules, nil, GuardConfig{})
	cves := make([]string, 0, len(candidates))
	for cve := range candidates {
		cves = append(cves, cve)
	}
	signals, err := loadSignals(ctx, tx, cves)
	if err != nil {
		return Result{}, err
	}
	want := Decide(findings, host, rules, signals, GuardConfig{Exploit: cfg.GuardExploit, EPSS: cfg.GuardEPSS})

	have, err := loadDecisions(ctx, tx, serverID)
	if err != nil {
		return Result{}, err
	}
	e.holdUnsettled(want, have, host, cfg)

	var res Result
	for cve, d := range want {
		old, exists := have[cve]
		switch {
		case !exists:
			res.Created++
			if err := writeDecision(ctx, tx, serverID, d, "auto_created"); err != nil {
				return Result{}, err
			}
		case !old.equal(d):
			res.Changed++
			if err := writeDecision(ctx, tx, serverID, d, "auto_changed"); err != nil {
				return Result{}, err
			}
		}
	}
	for cve, old := range have {
		if _, keep := want[cve]; keep {
			continue
		}
		res.Revoked++
		if _, err := tx.Exec(ctx, `DELETE FROM auto_decisions WHERE server_id = $1 AND cve_id = $2`, serverID, cve); err != nil {
			return Result{}, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO decision_events (server_id, cve_id, event, verdict, rule_ids, guards, reason, evidence)
			VALUES ($1, $2, 'auto_revoked', $3, $4, $5, $6, $7)
		`, serverID, cve, old.verdict, old.ruleIDs, old.guards, revokeReason(findings, cve, old.ruleIDs, rules, host, cfg), old.evidence); err != nil {
			return Result{}, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return Result{}, err
	}
	metrics.AutoDecisionChangesTotal.WithLabelValues("created").Add(float64(res.Created))
	metrics.AutoDecisionChangesTotal.WithLabelValues("changed").Add(float64(res.Changed))
	metrics.AutoDecisionChangesTotal.WithLabelValues("revoked").Add(float64(res.Revoked))
	return res, nil
}

// holdUnsettled drops new decisions that rest on runtime facts which changed
// less than the settle window ago. A decision that exists already is kept (and
// updated) as long as its rules still hold; only its creation waits.
func (e *Evaluator) holdUnsettled(want map[string]Decision, have map[string]storedDecision, h *Host, cfg services.AutoAssessmentConfig) {
	window := time.Duration(cfg.FactSettleMinutes) * time.Minute
	if window <= 0 {
		return
	}
	for cve, d := range want {
		if _, exists := have[cve]; exists {
			continue
		}
		for cat := range d.Evidence.Facts {
			// The service list carries each unit's running state, which
			// changes whenever a timer job runs, so it is practically never
			// unchanged for long. The checks read only which units are
			// installed or masked, a deliberate change; a decision is still
			// revoked at once when that changes.
			if cat == "services" {
				continue
			}
			if age, ok := h.FactsAge[cat]; !ok || age < window {
				delete(want, cve)
				break
			}
		}
	}
}

// revokeReason explains why a decision no longer holds: per finding of the
// CVE that is no longer dismissed, why each rule of the old decision does not
// dismiss it any more.
func revokeReason(findings []Finding, cve string, oldRules []string, enabled []Rule, h *Host, cfg services.AutoAssessmentConfig) string {
	var fs []Finding
	for _, f := range findings {
		if f.CVEID == cve {
			fs = append(fs, f)
		}
	}
	if len(fs) == 0 {
		return "the CVE has no active findings on this server any more (fixed or package removed)"
	}
	active := map[string]Rule{}
	for _, r := range enabled {
		active[r.ID()] = r
	}
	var parts []string
	for _, f := range fs {
		dismissed := false
		for _, r := range enabled {
			if ok, _ := r.Dismiss(f, h); ok {
				dismissed = true
				break
			}
		}
		if dismissed {
			continue
		}
		var why []string
		for _, id := range oldRules {
			r, on := active[id]
			if !on {
				why = append(why, id+" is switched off")
				continue
			}
			if _, reason := r.Dismiss(f, h); reason != "" {
				why = append(why, id+": "+reason)
			}
		}
		if len(why) == 0 {
			why = append(why, "no enabled rule dismisses it")
		}
		parts = append(parts, f.Package+" — "+strings.Join(why, "; "))
	}
	if len(parts) == 0 {
		return "no enabled rule dismisses every finding of the CVE any more"
	}
	if cfg.Mode == services.AutoModeOff {
		return "automated assessment is off"
	}
	return strings.Join(parts, " | ")
}

type storedDecision struct {
	verdict  string
	ruleIDs  []string
	guards   []string
	reason   string
	evidence []byte
}

func (s storedDecision) equal(d Decision) bool {
	return s.verdict == d.Verdict && slices.Equal(s.ruleIDs, d.RuleIDs) &&
		slices.Equal(s.guards, d.Guards) && s.reason == d.Reason &&
		jsonEqual(s.evidence, d.EvidenceJSON())
}

// jsonEqual compares two JSON documents after Postgres's JSONB normalisation
// (key order and whitespace may differ from what was written).
func jsonEqual(a, b []byte) bool {
	var ca, cb bytes.Buffer
	if err := compactCanonical(&ca, a); err != nil {
		return false
	}
	if err := compactCanonical(&cb, b); err != nil {
		return false
	}
	return bytes.Equal(ca.Bytes(), cb.Bytes())
}

func loadFindings(ctx context.Context, tx pgx.Tx, serverID int64) ([]Finding, error) {
	rows, err := tx.Query(ctx, `
		SELECT cve_id, package_name, COALESCE(package_version, ''), COALESCE(fix_state, ''),
		       COALESCE(vex_status, ''), COALESCE(vex_justification, '')
		FROM findings
		WHERE server_id = $1 AND resolved_at IS NULL
	`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.CVEID, &f.Package, &f.PackageVersion, &f.FixState, &f.VexStatus, &f.VexJustification); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func loadSignals(ctx context.Context, tx pgx.Tx, cves []string) (map[string]CVESignals, error) {
	out := map[string]CVESignals{}
	if len(cves) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT c.cve_id, kev.cve_id IS NOT NULL, ep.epss::float8,
		       EXISTS (SELECT 1 FROM exploits e WHERE e.cve_ids @> ARRAY[c.cve_id::text] AND e.verified)
		FROM unnest($1::text[]) AS c(cve_id)
		LEFT JOIN kev_entries kev ON kev.cve_id = c.cve_id
		LEFT JOIN epss_scores ep ON ep.cve_id = c.cve_id
	`, cves)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var s CVESignals
		if err := rows.Scan(&id, &s.InKEV, &s.EPSS, &s.VerifiedExploit); err != nil {
			return nil, err
		}
		out[id] = s
	}
	return out, rows.Err()
}

func loadDecisions(ctx context.Context, tx pgx.Tx, serverID int64) (map[string]storedDecision, error) {
	rows, err := tx.Query(ctx, `
		SELECT cve_id, verdict, rule_ids, guards, reason, evidence
		FROM auto_decisions WHERE server_id = $1
	`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]storedDecision{}
	for rows.Next() {
		var cve string
		var d storedDecision
		if err := rows.Scan(&cve, &d.verdict, &d.ruleIDs, &d.guards, &d.reason, &d.evidence); err != nil {
			return nil, err
		}
		out[cve] = d
	}
	return out, rows.Err()
}

func writeDecision(ctx context.Context, tx pgx.Tx, serverID int64, d Decision, event string) error {
	ev := d.EvidenceJSON()
	if _, err := tx.Exec(ctx, `
		INSERT INTO auto_decisions (server_id, cve_id, verdict, source, rule_ids, guards, reason, evidence, decided_at, updated_at)
		VALUES ($1, $2, $3, $8, $4, $5, $6, $7, NOW(), NOW())
		ON CONFLICT (server_id, cve_id) DO UPDATE SET
			verdict = EXCLUDED.verdict, source = EXCLUDED.source, rule_ids = EXCLUDED.rule_ids,
			guards = EXCLUDED.guards, reason = EXCLUDED.reason, evidence = EXCLUDED.evidence,
			updated_at = NOW()
	`, serverID, d.CVEID, d.Verdict, d.RuleIDs, d.Guards, d.Reason, ev, decisionSource(d)); err != nil {
		return fmt.Errorf("store decision %s: %w", d.CVEID, err)
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO decision_events (server_id, cve_id, event, verdict, rule_ids, guards, reason, evidence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, serverID, d.CVEID, event, d.Verdict, d.RuleIDs, d.Guards, d.Reason, ev)
	return err
}

// decisionSource is "ai" when the AI precondition analysis took part.
func decisionSource(d Decision) string {
	if slices.Contains(d.RuleIDs, "AI-PRE") {
		return "ai"
	}
	return "rule"
}

// EvaluateAll re-evaluates every server. Used after a KEV/EPSS sync, a settings
// change and at start-up (a new release may change a rule). Concurrent calls are
// coalesced: while one run is in progress, further calls schedule exactly one
// more run.
func (e *Evaluator) EvaluateAll(ctx context.Context, trigger string) {
	e.allMu.Lock()
	if e.allRunning {
		if !slices.Contains(e.allPending, trigger) {
			e.allPending = append(e.allPending, trigger)
		}
		e.allMu.Unlock()
		return
	}
	e.allRunning = true
	e.allMu.Unlock()

	for {
		e.evaluateAllOnce(ctx, trigger)
		e.allMu.Lock()
		if len(e.allPending) == 0 {
			e.allRunning = false
			e.allMu.Unlock()
			return
		}
		trigger = strings.Join(e.allPending, ", ")
		e.allPending = nil
		e.allMu.Unlock()
	}
}

func (e *Evaluator) evaluateAllOnce(ctx context.Context, trigger string) {
	start := time.Now()
	cfg, err := e.settings.LoadAutoAssessmentConfig(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Automated assessment: load configuration")
		return
	}
	if cfg.Mode == services.AutoModeOff {
		return
	}
	rows, err := e.db.Query(ctx, `SELECT id FROM servers ORDER BY id`)
	if err != nil {
		log.Error().Err(err).Msg("Automated assessment: list servers")
		return
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		log.Error().Err(err).Msg("Automated assessment: list servers")
		return
	}
	var total Result
	for _, id := range ids {
		r, err := e.evaluateServer(ctx, id, cfg)
		if err != nil {
			log.Error().Err(err).Int64("serverId", id).Msg("Automated assessment: evaluate server")
			continue
		}
		total.add(r)
	}
	log.Info().Str("trigger", trigger).Int("servers", len(ids)).
		Int("created", total.Created).Int("changed", total.Changed).Int("revoked", total.Revoked).
		Dur("duration", time.Since(start)).Msg("Automated assessment: all servers re-evaluated")
}

// TriggerAll runs EvaluateAll in the background.
func (e *Evaluator) TriggerAll(trigger string) {
	go e.EvaluateAll(context.Background(), trigger)
}
