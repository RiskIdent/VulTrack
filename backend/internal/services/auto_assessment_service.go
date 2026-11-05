package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/models"
)

// AutoAssessmentService reads automated decisions and manages per-server human
// decisions. Decisions are written by the autoassess evaluator.
type AutoAssessmentService struct {
	db *pgxpool.Pool

	// The pair counts in Stats scan every active finding; they change only
	// with scans, so they are reused for pairCacheTTL (per set of active rules).
	pairMu    sync.Mutex
	pairKey   string
	pairAt    time.Time
	pairTotal int
	pairOpen  int
}

const pairCacheTTL = 60 * time.Second

// NewAutoAssessmentService creates an AutoAssessmentService.
func NewAutoAssessmentService(db *pgxpool.Pool) *AutoAssessmentService {
	return &AutoAssessmentService{db: db}
}

// Decision states, as shown in the UI and reports:
const (
	DecisionApplied    = "applied"    // in effect: the server is removed from the triage queue
	DecisionShadow     = "shadow"     // computed, not in effect (global or rule mode)
	DecisionBlocked    = "blocked"    // a guard prevents it
	DecisionRejected   = "rejected"   // a human switched automation off for this server
	DecisionOverridden = "overridden" // a human decided for this server, or bindingly for the CVE
)

// decisionStateSQL computes the state of an auto_decisions row d, given the
// per-server override o, the CVE assessment a and the active rules bound as the
// text[] parameter $active.
func decisionStateSQL(active string) string {
	return `CASE
		WHEN o.status IS NOT NULL AND o.status <> 'manual' THEN 'overridden'
		WHEN a.binding_all_servers AND a.status <> 'pending' THEN 'overridden'
		WHEN o.status = 'manual' THEN 'rejected'
		WHEN cardinality(d.guards) > 0 THEN 'blocked'
		WHEN d.rule_ids <@ ` + active + `::text[] THEN 'applied'
		ELSE 'shadow'
	END`
}

// AutoDecision is one stored decision with its current state.
type AutoDecision struct {
	ServerID   int64           `json:"serverId"`
	ServerName string          `json:"serverName"`
	CVEID      string          `json:"cveId"`
	Verdict    string          `json:"verdict"`
	Source     string          `json:"source"`
	RuleIDs    []string        `json:"ruleIds"`
	Guards     []string        `json:"guards"`
	Reason     string          `json:"reason"`
	Evidence   json.RawMessage `json:"evidence"`
	State      string          `json:"state"`
	DecidedAt  time.Time       `json:"decidedAt"`
	UpdatedAt  time.Time       `json:"updatedAt"`
	// The human verdict for the same server, if any: a per-server decision or
	// the CVE assessment. Used to judge agreement.
	HumanStatus string `json:"humanStatus,omitempty"`
}

// DecisionFilter narrows ListDecisions.
type DecisionFilter struct {
	RuleID   string
	State    string // one of the Decision* states
	Guard    string
	ServerID int64
	CVEID    string
	Search   string // CVE ID or server name contains
	Limit    int
	Offset   int
}

const decisionFrom = `
	FROM auto_decisions d
	JOIN servers srv ON srv.id = d.server_id
	LEFT JOIN assessment_overrides o ON o.server_id = d.server_id AND o.cve_id = d.cve_id
	LEFT JOIN assessments a ON a.cve_id = d.cve_id`

// humanStatusSQL is the human verdict on a decision's server.
const humanStatusSQL = `COALESCE(NULLIF(o.status, 'manual'), NULLIF(a.status, 'pending'), '')`

// ListDecisions returns stored decisions with their state, newest first.
func (s *AutoAssessmentService) ListDecisions(ctx context.Context, cfg AutoAssessmentConfig, f DecisionFilter) ([]AutoDecision, int, error) {
	args := []any{cfg.ActiveRuleIDs()}
	state := decisionStateSQL("$1")
	// $1 is referenced even without a state filter, so Postgres can type it.
	where := []string{"$1::text[] IS NOT NULL"}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "$?", "$"+strconv.Itoa(len(args))))
	}
	if f.RuleID != "" {
		add("$? = ANY(d.rule_ids)", f.RuleID)
	}
	if f.Guard != "" {
		add("$? = ANY(d.guards)", f.Guard)
	}
	if f.State != "" {
		add("("+state+") = $?", f.State)
	}
	if f.ServerID > 0 {
		add("d.server_id = $?", f.ServerID)
	}
	if f.CVEID != "" {
		add("d.cve_id = $?", f.CVEID)
	}
	if q := strings.TrimSpace(f.Search); q != "" {
		add("(d.cve_id ILIKE $? OR srv.name ILIKE $?)", "%"+escapeLike(q)+"%")
	}
	whereSQL := " WHERE " + strings.Join(where, " AND ")

	var total int
	if err := s.db.QueryRow(ctx, "SELECT COUNT(*)"+decisionFrom+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	f.Limit, f.Offset = normalizePage(f.Limit, f.Offset)
	args = append(args, f.Limit, f.Offset)
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
		SELECT d.server_id, srv.name, d.cve_id, d.verdict, d.source, d.rule_ids, d.guards, d.reason,
		       d.evidence, %s, d.decided_at, d.updated_at, %s
		%s %s
		ORDER BY d.updated_at DESC, d.server_id, d.cve_id
		LIMIT $%d OFFSET $%d
	`, state, humanStatusSQL, decisionFrom, whereSQL, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []AutoDecision{}
	for rows.Next() {
		var d AutoDecision
		if err := rows.Scan(&d.ServerID, &d.ServerName, &d.CVEID, &d.Verdict, &d.Source, &d.RuleIDs, &d.Guards,
			&d.Reason, &d.Evidence, &d.State, &d.DecidedAt, &d.UpdatedAt, &d.HumanStatus); err != nil {
			return nil, 0, err
		}
		out = append(out, d)
	}
	return out, total, rows.Err()
}

// RuleStats counts the decisions a rule took part in.
type RuleStats struct {
	RuleID     string `json:"ruleId"`
	Decisions  int    `json:"decisions"`
	Applied    int    `json:"applied"`
	Shadow     int    `json:"shadow"`
	Blocked    int    `json:"blocked"`
	Rejected   int    `json:"rejected"`
	Overridden int    `json:"overridden"`
	// Agreement with humans on the same (server, CVE): the human verdict is the
	// per-server decision, else the CVE assessment.
	HumanAgree    int `json:"humanAgree"`    // human said not_relevant
	HumanDisagree int `json:"humanDisagree"` // human said relevant or accepted_risk
}

// DayCount is one day of decision activity.
type DayCount struct {
	Date      string `json:"date"`
	Created   int    `json:"created"`
	Revoked   int    `json:"revoked"`
	Overrides int    `json:"overrides"`
}

// AutoAssessmentStats summarises the automated assessment.
type AutoAssessmentStats struct {
	Rules       []RuleStats    `json:"rules"`
	Guards      map[string]int `json:"guards"` // decisions blocked per guard
	Total       RuleStats      `json:"total"`
	OpenPairs   int            `json:"openPairs"`   // (server, CVE) pairs with active findings and no decision of any kind
	TotalPairs  int            `json:"totalPairs"`  // (server, CVE) pairs with active findings
	Overrides   map[string]int `json:"overrides"`   // per-server human decisions by status
	Activity    []DayCount     `json:"activity"`    // last 30 days
	LastEventAt *time.Time     `json:"lastEventAt"` // newest decision event
}

// Stats summarises decisions per rule and overall.
func (s *AutoAssessmentService) Stats(ctx context.Context, cfg AutoAssessmentConfig) (*AutoAssessmentStats, error) {
	st := &AutoAssessmentStats{Guards: map[string]int{}, Overrides: map[string]int{}, Activity: []DayCount{}}
	active := cfg.ActiveRuleIDs()
	counts := `
		COUNT(*),
		COUNT(*) FILTER (WHERE state = 'applied'),
		COUNT(*) FILTER (WHERE state = 'shadow'),
		COUNT(*) FILTER (WHERE state = 'blocked'),
		COUNT(*) FILTER (WHERE state = 'rejected'),
		COUNT(*) FILTER (WHERE state = 'overridden'),
		COUNT(*) FILTER (WHERE human = 'not_relevant'),
		COUNT(*) FILTER (WHERE human IN ('relevant', 'accepted_risk'))`
	base := `SELECT d.rule_ids, d.guards, ` + decisionStateSQL("$1") + ` AS state, ` + humanStatusSQL + ` AS human` + decisionFrom

	rows, err := s.db.Query(ctx, `
		WITH x AS (`+base+`)
		SELECT r.rule_id, `+counts+`
		FROM x, unnest(x.rule_ids) AS r(rule_id)
		GROUP BY r.rule_id ORDER BY r.rule_id
	`, active)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r RuleStats
		if err := rows.Scan(&r.RuleID, &r.Decisions, &r.Applied, &r.Shadow, &r.Blocked, &r.Rejected, &r.Overridden, &r.HumanAgree, &r.HumanDisagree); err != nil {
			rows.Close()
			return nil, err
		}
		st.Rules = append(st.Rules, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	t := &st.Total
	if err := s.db.QueryRow(ctx, `WITH x AS (`+base+`) SELECT 'total', `+counts+` FROM x`, active).
		Scan(&t.RuleID, &t.Decisions, &t.Applied, &t.Shadow, &t.Blocked, &t.Rejected, &t.Overridden, &t.HumanAgree, &t.HumanDisagree); err != nil {
		return nil, err
	}

	rows, err = s.db.Query(ctx, `SELECT g, COUNT(*) FROM auto_decisions, unnest(guards) g GROUP BY g`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var g string
		var n int
		if err := rows.Scan(&g, &n); err != nil {
			rows.Close()
			return nil, err
		}
		st.Guards[g] = n
	}
	rows.Close()

	rows, err = s.db.Query(ctx, `SELECT status, COUNT(*) FROM assessment_overrides GROUP BY status`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			rows.Close()
			return nil, err
		}
		st.Overrides[k] = n
	}
	rows.Close()

	st.TotalPairs, st.OpenPairs, err = s.pairCounts(ctx, active)
	if err != nil {
		return nil, err
	}

	rows, err = s.db.Query(ctx, `
		SELECT to_char(day, 'YYYY-MM-DD'),
		       COUNT(e.id) FILTER (WHERE e.event = 'auto_created'),
		       COUNT(e.id) FILTER (WHERE e.event = 'auto_revoked'),
		       COUNT(e.id) FILTER (WHERE e.event IN ('override_set', 'override_removed'))
		FROM generate_series(CURRENT_DATE - 29, CURRENT_DATE, interval '1 day') AS day
		LEFT JOIN decision_events e ON e.created_at >= day AND e.created_at < day + interval '1 day'
		GROUP BY day ORDER BY day
	`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var d DayCount
		if err := rows.Scan(&d.Date, &d.Created, &d.Revoked, &d.Overrides); err != nil {
			rows.Close()
			return nil, err
		}
		st.Activity = append(st.Activity, d)
	}
	rows.Close()

	if err := s.db.QueryRow(ctx, `SELECT MAX(created_at) FROM decision_events`).Scan(&st.LastEventAt); err != nil {
		return nil, err
	}
	return st, nil
}

// CountByRuleAndState counts stored decisions per [rule, state].
func (s *AutoAssessmentService) CountByRuleAndState(ctx context.Context, cfg AutoAssessmentConfig) (map[[2]string]int, error) {
	rows, err := s.db.Query(ctx, `
		WITH x AS (SELECT d.rule_ids, `+decisionStateSQL("$1")+` AS state`+decisionFrom+`)
		SELECT r, state, COUNT(*) FROM x, unnest(x.rule_ids) AS r GROUP BY r, state
	`, cfg.ActiveRuleIDs())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[[2]string]int{}
	for rows.Next() {
		var rule, state string
		var n int
		if err := rows.Scan(&rule, &state, &n); err != nil {
			return nil, err
		}
		out[[2]string{rule, state}] = n
	}
	return out, rows.Err()
}

// pairCounts returns the (server, CVE) pairs with active findings and those
// nothing has decided yet (no automated decision in effect, no human decision
// for the server or the CVE), cached for pairCacheTTL.
func (s *AutoAssessmentService) pairCounts(ctx context.Context, active []string) (int, int, error) {
	key := strings.Join(active, ",")
	s.pairMu.Lock()
	defer s.pairMu.Unlock()
	if s.pairKey == key && !s.pairAt.IsZero() && time.Since(s.pairAt) < pairCacheTTL {
		return s.pairTotal, s.pairOpen, nil
	}
	var total, open int
	if err := s.db.QueryRow(ctx, `
		WITH pairs AS (
			SELECT server_id, cve_id FROM findings WHERE resolved_at IS NULL GROUP BY server_id, cve_id
		)
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE NOT (
		           (o.status IS NOT NULL AND o.status <> 'manual')
		           OR (a.id IS NOT NULL AND a.status <> 'pending')
		           OR (o.status IS NULL AND d.server_id IS NOT NULL AND cardinality(d.guards) = 0 AND d.rule_ids <@ $1::text[])
		       ))
		FROM pairs p
		LEFT JOIN assessment_overrides o ON o.server_id = p.server_id AND o.cve_id = p.cve_id
		LEFT JOIN assessments a ON a.cve_id = p.cve_id
		LEFT JOIN auto_decisions d ON d.server_id = p.server_id AND d.cve_id = p.cve_id
	`, active).Scan(&total, &open); err != nil {
		return 0, 0, err
	}
	s.pairKey, s.pairAt, s.pairTotal, s.pairOpen = key, time.Now(), total, open
	return total, open, nil
}

// DecisionEvent is one entry of the audit trail.
type DecisionEvent struct {
	ID         int64           `json:"id"`
	ServerID   int64           `json:"serverId"`
	ServerName string          `json:"serverName"`
	CVEID      string          `json:"cveId"`
	Event      string          `json:"event"`
	Verdict    *string         `json:"verdict,omitempty"`
	RuleIDs    []string        `json:"ruleIds,omitempty"`
	Guards     []string        `json:"guards,omitempty"`
	Reason     *string         `json:"reason,omitempty"`
	Evidence   json.RawMessage `json:"evidence,omitempty"`
	Actor      *string         `json:"actor,omitempty"`
	CreatedAt  time.Time       `json:"createdAt"`
}

// Events returns the audit trail, newest first, optionally for one server
// and/or CVE.
func (s *AutoAssessmentService) Events(ctx context.Context, serverID int64, cveID string, limit int) ([]DecisionEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(ctx, `
		SELECT e.id, e.server_id, srv.name, e.cve_id, e.event, e.verdict, e.rule_ids, e.guards,
		       e.reason, e.evidence, e.actor, e.created_at
		FROM decision_events e JOIN servers srv ON srv.id = e.server_id
		WHERE ($1::bigint = 0 OR e.server_id = $1) AND ($2 = '' OR e.cve_id = $2)
		ORDER BY e.created_at DESC, e.id DESC
		LIMIT $3
	`, serverID, cveID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DecisionEvent{}
	for rows.Next() {
		var e DecisionEvent
		if err := rows.Scan(&e.ID, &e.ServerID, &e.ServerName, &e.CVEID, &e.Event, &e.Verdict, &e.RuleIDs, &e.Guards,
			&e.Reason, &e.Evidence, &e.Actor, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Override is a human decision for one server.
type Override struct {
	Status     string    `json:"status"`
	Comment    string    `json:"comment,omitempty"`
	AssessedBy string    `json:"assessedBy,omitempty"`
	AssessedAt time.Time `json:"assessedAt"`
}

// ServerStatus is the effective status of one affected server for a CVE.
type ServerStatus struct {
	ServerID   int64         `json:"serverId"`
	ServerName string        `json:"serverName"`
	Packages   []string      `json:"packages"`
	Status     string        `json:"status"` // open, not_relevant, relevant, accepted_risk
	Source     string        `json:"source"` // override, binding, auto, assessment, none
	Override   *Override     `json:"override,omitempty"`
	Decision   *AutoDecision `json:"decision,omitempty"`
}

// CVEServerStatuses returns, for every server with an active finding of the
// CVE, its effective status and where it comes from (precedence in
// docs/AUTO_ASSESSMENT_PLAN.md §3.1).
func (s *AutoAssessmentService) CVEServerStatuses(ctx context.Context, cfg AutoAssessmentConfig, cveID string) ([]ServerStatus, error) {
	rows, err := s.db.Query(ctx, `
		SELECT f.server_id, srv.name, ARRAY_AGG(DISTINCT f.package_name ORDER BY f.package_name),
		       o.status, COALESCE(o.comment, ''), COALESCE(o.assessed_by, ''), o.assessed_at,
		       a.status, COALESCE(a.binding_all_servers, false),
		       d.server_id IS NOT NULL, d.verdict, d.source, d.rule_ids, d.guards, d.reason, d.evidence,
		       d.decided_at, d.updated_at
		FROM findings f
		JOIN servers srv ON srv.id = f.server_id
		LEFT JOIN assessment_overrides o ON o.server_id = f.server_id AND o.cve_id = f.cve_id
		LEFT JOIN assessments a ON a.cve_id = f.cve_id
		LEFT JOIN auto_decisions d ON d.server_id = f.server_id AND d.cve_id = f.cve_id
		WHERE f.cve_id = $1 AND f.resolved_at IS NULL
		GROUP BY f.server_id, srv.name, o.status, o.comment, o.assessed_by, o.assessed_at,
		         a.status, a.binding_all_servers, d.server_id, d.verdict, d.source, d.rule_ids, d.guards,
		         d.reason, d.evidence, d.decided_at, d.updated_at
		ORDER BY srv.name
	`, cveID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	active := map[string]bool{}
	for _, id := range cfg.ActiveRuleIDs() {
		active[id] = true
	}

	out := []ServerStatus{}
	for rows.Next() {
		var st ServerStatus
		var oStatus, aStatus, dVerdict, dSource, dReason *string
		var oComment, oBy string
		var oAt, dDecided, dUpdated *time.Time
		var binding, hasDecision bool
		var dRules, dGuards []string
		var dEvidence []byte
		if err := rows.Scan(&st.ServerID, &st.ServerName, &st.Packages,
			&oStatus, &oComment, &oBy, &oAt, &aStatus, &binding,
			&hasDecision, &dVerdict, &dSource, &dRules, &dGuards, &dReason, &dEvidence, &dDecided, &dUpdated); err != nil {
			return nil, err
		}
		if oStatus != nil {
			st.Override = &Override{Status: *oStatus, Comment: oComment, AssessedBy: oBy, AssessedAt: *oAt}
		}
		humanCVE := aStatus != nil && *aStatus != "pending"

		if hasDecision {
			d := &AutoDecision{ServerID: st.ServerID, ServerName: st.ServerName, CVEID: cveID,
				Verdict: *dVerdict, Source: *dSource, RuleIDs: dRules, Guards: dGuards, Reason: *dReason,
				Evidence: dEvidence, DecidedAt: *dDecided, UpdatedAt: *dUpdated}
			allActive := len(dRules) > 0
			for _, r := range dRules {
				allActive = allActive && active[r]
			}
			switch {
			case oStatus != nil && *oStatus != "manual", binding && humanCVE:
				d.State = DecisionOverridden
			case oStatus != nil:
				d.State = DecisionRejected
			case len(dGuards) > 0:
				d.State = DecisionBlocked
			case allActive:
				d.State = DecisionApplied
			default:
				d.State = DecisionShadow
			}
			st.Decision = d
		}

		switch {
		case oStatus != nil && *oStatus != "manual":
			st.Status, st.Source = *oStatus, "override"
		case binding && humanCVE:
			st.Status, st.Source = *aStatus, "binding"
		case oStatus == nil && st.Decision != nil && st.Decision.State == DecisionApplied:
			st.Status, st.Source = st.Decision.Verdict, "auto"
		case humanCVE:
			st.Status, st.Source = *aStatus, "assessment"
		default:
			st.Status, st.Source = "open", "none"
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// ValidOverrideStatuses are the statuses of a per-server human decision.
var ValidOverrideStatuses = map[string]bool{"relevant": true, "not_relevant": true, "accepted_risk": true, "manual": true}

// ErrInvalidOverride is returned for an unknown override status.
var ErrInvalidOverride = errors.New("invalid status; use relevant, not_relevant, accepted_risk or manual")

// SetOverride stores a human decision for one server and records it in the
// audit trail.
func (s *AutoAssessmentService) SetOverride(ctx context.Context, serverID int64, cveID, status, comment, actor string) (*Override, error) {
	if !ValidOverrideStatuses[status] {
		return nil, ErrInvalidOverride
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var o Override
	err = tx.QueryRow(ctx, `
		INSERT INTO assessment_overrides (server_id, cve_id, status, comment, assessed_by, assessed_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (server_id, cve_id) DO UPDATE SET
			status = EXCLUDED.status, comment = EXCLUDED.comment,
			assessed_by = EXCLUDED.assessed_by, assessed_at = NOW()
		RETURNING status, COALESCE(comment, ''), COALESCE(assessed_by, ''), assessed_at
	`, serverID, cveID, status, comment, actor).Scan(&o.Status, &o.Comment, &o.AssessedBy, &o.AssessedAt)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO decision_events (server_id, cve_id, event, verdict, reason, actor)
		VALUES ($1, $2, 'override_set', $3, NULLIF($4, ''), NULLIF($5, ''))
	`, serverID, cveID, status, comment, actor); err != nil {
		return nil, err
	}
	return &o, tx.Commit(ctx)
}

// RemoveOverride deletes a per-server human decision. It reports false when
// there was none.
func (s *AutoAssessmentService) RemoveOverride(ctx context.Context, serverID int64, cveID, actor string) (bool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var old string
	err = tx.QueryRow(ctx, `DELETE FROM assessment_overrides WHERE server_id = $1 AND cve_id = $2 RETURNING status`, serverID, cveID).Scan(&old)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO decision_events (server_id, cve_id, event, verdict, actor)
		VALUES ($1, $2, 'override_removed', $3, NULLIF($4, ''))
	`, serverID, cveID, old, actor); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// DecisionsForPairs returns the stored decision of each (server, CVE) pair
// that has one, keyed "serverID|cveID".
func (s *AutoAssessmentService) DecisionsForPairs(ctx context.Context, cfg AutoAssessmentConfig, serverIDs []int64, cveIDs []string) (map[string]models.DecisionBadge, error) {
	out := map[string]models.DecisionBadge{}
	if len(serverIDs) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(ctx, `
		SELECT d.server_id, d.cve_id, d.rule_ids, d.guards, `+decisionStateSQL("$1")+`
		FROM unnest($2::bigint[], $3::text[]) AS p(server_id, cve_id)
		JOIN auto_decisions d ON d.server_id = p.server_id AND d.cve_id = p.cve_id
		LEFT JOIN assessment_overrides o ON o.server_id = d.server_id AND o.cve_id = d.cve_id
		LEFT JOIN assessments a ON a.cve_id = d.cve_id
	`, cfg.ActiveRuleIDs(), serverIDs, cveIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sid int64
		var cve string
		var b models.DecisionBadge
		if err := rows.Scan(&sid, &cve, &b.RuleIDs, &b.Guards, &b.State); err != nil {
			return nil, err
		}
		out[fmt.Sprintf("%d|%s", sid, cve)] = b
	}
	return out, rows.Err()
}

// AttachToFindings sets AutoDecision on the findings whose (server, CVE) pair
// has a stored decision. With automation off nothing is attached.
func (s *AutoAssessmentService) AttachToFindings(ctx context.Context, cfg AutoAssessmentConfig, findings []models.Finding) error {
	if cfg.Mode == AutoModeOff || len(findings) == 0 {
		return nil
	}
	sids := make([]int64, len(findings))
	cves := make([]string, len(findings))
	for i, f := range findings {
		sids[i], cves[i] = f.ServerID, f.CVEID
	}
	m, err := s.DecisionsForPairs(ctx, cfg, sids, cves)
	if err != nil {
		return err
	}
	for i := range findings {
		if b, ok := m[fmt.Sprintf("%d|%s", findings[i].ServerID, findings[i].CVEID)]; ok {
			findings[i].AutoDecision = &b
		}
	}
	return nil
}

// AttachToGroups is AttachToFindings for findings grouped by (server, CVE).
func (s *AutoAssessmentService) AttachToGroups(ctx context.Context, cfg AutoAssessmentConfig, groups []models.GroupedFinding) error {
	if cfg.Mode == AutoModeOff || len(groups) == 0 {
		return nil
	}
	sids := make([]int64, len(groups))
	cves := make([]string, len(groups))
	for i, g := range groups {
		sids[i], cves[i] = g.ServerID, g.CVEID
	}
	m, err := s.DecisionsForPairs(ctx, cfg, sids, cves)
	if err != nil {
		return err
	}
	for i := range groups {
		if b, ok := m[fmt.Sprintf("%d|%s", groups[i].ServerID, groups[i].CVEID)]; ok {
			groups[i].AutoDecision = &b
		}
	}
	return nil
}

// ExcludedFromTicket returns the servers that a new "relevant" assessment of the
// CVE does not cover: servers with a per-server decision other than relevant,
// and servers an applied automated decision dismissed. A binding assessment
// covers every server, so then the result is empty.
func (s *AutoAssessmentService) ExcludedFromTicket(ctx context.Context, cfg AutoAssessmentConfig, cveID string, binding bool) (map[int64]string, error) {
	statuses, err := s.CVEServerStatuses(ctx, cfg, cveID)
	if err != nil {
		return nil, err
	}
	out := map[int64]string{}
	if binding {
		return out, nil
	}
	for _, st := range statuses {
		switch {
		case st.Override != nil && st.Override.Status != "manual" && st.Override.Status != "relevant":
			out[st.ServerID] = "decided individually: " + st.Override.Status
		case st.Override == nil && st.Decision != nil && st.Decision.State == DecisionApplied:
			out[st.ServerID] = "automatically assessed as not relevant (" + strings.Join(st.Decision.RuleIDs, ", ") + ")"
		}
	}
	return out, nil
}
