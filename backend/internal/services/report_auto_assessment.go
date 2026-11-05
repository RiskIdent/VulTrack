package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/border"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"
)

// AutoAssessmentReport is the "Automated assessments" section of the PDF
// report, limited to the report's servers.
type AutoAssessmentReport struct {
	Mode        string
	ActiveRules []string
	Rules       []AutoReportRule
	// Changes in the report period
	Created, Revoked int
	// Per-server human decisions made in the period (newest first, at most 50)
	Overrides      []AutoReportOverride
	OverridesTotal int
	// CVEs dismissed by applied decisions, by number of servers (at most 25)
	Dismissed      []AutoReportCVE
	DismissedTotal int
}

// AutoReportRule is one row of the per-rule table.
type AutoReportRule struct {
	RuleID        string
	Description   string
	Applied       int
	Shadow        int
	Blocked       int
	Overridden    int // includes "rejected" (automation switched off by a human)
	HumanAgree    int
	HumanAccepted int
	HumanDisagree int
}

// AutoReportOverride is one per-server human decision.
type AutoReportOverride struct {
	At      time.Time
	Server  string
	CVEID   string
	Status  string
	Actor   string
	Comment string
}

// AutoReportCVE is one CVE dismissed by applied decisions.
type AutoReportCVE struct {
	CVEID   string
	Servers int
	Rules   string
}

// serverScope returns a condition restricting column to the report's servers
// and appends the argument; no condition when the report covers all servers.
func serverScope(column string, serverIDs []int64, args *[]any) string {
	if len(serverIDs) == 0 {
		return ""
	}
	*args = append(*args, serverIDs)
	return fmt.Sprintf(" AND %s = ANY($%d)", column, len(*args))
}

func (s *ReportService) getAutoAssessmentReport(ctx context.Context, serverIDs []int64, start, end time.Time, ruleDescriptions map[string]string) (*AutoAssessmentReport, error) {
	cfg, err := NewSettingsService(s.db).LoadAutoAssessmentConfig(ctx)
	if err != nil {
		return nil, err
	}
	r := &AutoAssessmentReport{Mode: cfg.Mode, ActiveRules: cfg.ActiveRuleIDs()}

	args := []any{r.ActiveRules}
	scope := serverScope("d.server_id", serverIDs, &args)
	rows, err := s.db.Query(ctx, `
		WITH x AS (
			SELECT d.rule_ids, `+decisionStateSQL("$1")+` AS state, `+humanStatusSQL+` AS human
			`+decisionFrom+`
			WHERE TRUE`+scope+`
		)
		SELECT rule_id,
		       COUNT(*) FILTER (WHERE state = 'applied'),
		       COUNT(*) FILTER (WHERE state = 'shadow'),
		       COUNT(*) FILTER (WHERE state = 'blocked'),
		       COUNT(*) FILTER (WHERE state IN ('overridden', 'rejected')),
		       COUNT(*) FILTER (WHERE human = 'not_relevant'),
		       COUNT(*) FILTER (WHERE human = 'accepted_risk'),
		       COUNT(*) FILTER (WHERE human = 'relevant')
		FROM x, unnest(x.rule_ids) AS rule_id
		GROUP BY rule_id ORDER BY rule_id
	`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var rr AutoReportRule
		if err := rows.Scan(&rr.RuleID, &rr.Applied, &rr.Shadow, &rr.Blocked, &rr.Overridden, &rr.HumanAgree, &rr.HumanAccepted, &rr.HumanDisagree); err != nil {
			rows.Close()
			return nil, err
		}
		rr.Description = ruleDescriptions[rr.RuleID]
		r.Rules = append(r.Rules, rr)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	eargs := []any{start, end}
	escope := serverScope("e.server_id", serverIDs, &eargs)
	if err := s.db.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE e.event = 'auto_created'), COUNT(*) FILTER (WHERE e.event = 'auto_revoked')
		FROM decision_events e
		WHERE e.created_at BETWEEN $1 AND $2`+escope, eargs...).Scan(&r.Created, &r.Revoked); err != nil {
		return nil, err
	}

	if err := s.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM decision_events e
		WHERE e.event = 'override_set' AND e.created_at BETWEEN $1 AND $2`+escope, eargs...).Scan(&r.OverridesTotal); err != nil {
		return nil, err
	}
	rows, err = s.db.Query(ctx, `
		SELECT e.created_at, srv.name, e.cve_id, COALESCE(e.verdict, ''), COALESCE(e.actor, ''), COALESCE(e.reason, '')
		FROM decision_events e JOIN servers srv ON srv.id = e.server_id
		WHERE e.event = 'override_set' AND e.created_at BETWEEN $1 AND $2`+escope+`
		ORDER BY e.created_at DESC LIMIT 50`, eargs...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var o AutoReportOverride
		if err := rows.Scan(&o.At, &o.Server, &o.CVEID, &o.Status, &o.Actor, &o.Comment); err != nil {
			rows.Close()
			return nil, err
		}
		r.Overrides = append(r.Overrides, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	dargs := []any{r.ActiveRules}
	dscope := serverScope("d.server_id", serverIDs, &dargs)
	applied := `
		WITH x AS (
			SELECT d.cve_id, d.server_id, d.rule_ids, ` + decisionStateSQL("$1") + ` AS state
			` + decisionFrom + `
			WHERE TRUE` + dscope + `
		)`
	if err := s.db.QueryRow(ctx, applied+` SELECT COUNT(DISTINCT cve_id) FROM x WHERE state = 'applied'`, dargs...).Scan(&r.DismissedTotal); err != nil {
		return nil, err
	}
	rows, err = s.db.Query(ctx, applied+`
		SELECT x.cve_id, COUNT(DISTINCT x.server_id),
		       (SELECT string_agg(DISTINCT r, ', ' ORDER BY r)
		        FROM x x2, unnest(x2.rule_ids) AS r
		        WHERE x2.cve_id = x.cve_id AND x2.state = 'applied')
		FROM x WHERE x.state = 'applied'
		GROUP BY x.cve_id
		ORDER BY 2 DESC, x.cve_id LIMIT 25`, dargs...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var c AutoReportCVE
		if err := rows.Scan(&c.CVEID, &c.Servers, &c.Rules); err != nil {
			rows.Close()
			return nil, err
		}
		r.Dismissed = append(r.Dismissed, c)
	}
	rows.Close()
	return r, rows.Err()
}

// addAutoAssessmentSection renders the "Automated assessments" section.
func (s *ReportService) addAutoAssessmentSection(m core.Maroto, data *ReportData) {
	r := data.AutoAssessment
	headerBg := &props.Color{Red: 41, Green: 82, Blue: 148}
	headerText := &props.Color{Red: 255, Green: 255, Blue: 255}
	zebraOdd := &props.Color{Red: 245, Green: 248, Blue: 253}
	grey := &props.Color{Red: 100, Green: 100, Blue: 100}
	headerCell := &props.Cell{BackgroundColor: headerBg, BorderType: border.Full, BorderColor: headerBg}
	rowCell := func(i int) *props.Cell {
		bg := &props.Color{Red: 255, Green: 255, Blue: 255}
		if i%2 == 1 {
			bg = zebraOdd
		}
		return &props.Cell{BackgroundColor: bg, BorderType: border.Full, BorderColor: headerBg}
	}
	h := func(s string, size float64, a align.Type) core.Component {
		return text.New(s, props.Text{Size: size, Style: fontstyle.Bold, Color: headerText, Align: a, Top: 1.5})
	}
	c := func(s string, size float64, a align.Type) core.Component {
		return text.New(s, props.Text{Size: size, Align: a, Top: 1.5})
	}

	m.AddRow(10, col.New(12).Add(text.New("Automated Assessments", props.Text{Size: 14, Style: fontstyle.Bold})))

	modeText := map[string]string{
		AutoModeOff:    "Off — no automated decisions are made.",
		AutoModeShadow: "Shadow — decisions are computed and shown, but none take effect.",
		AutoModeActive: "Active — decisions of the active rules remove servers from the triage queue.",
	}[r.Mode]
	active := "none"
	if len(r.ActiveRules) > 0 {
		active = strings.Join(r.ActiveRules, ", ")
	}
	m.AddAutoRow(col.New(12).Add(text.New(fmt.Sprintf(
		"Mode: %s Active rules: %s. Automation only ever dismisses findings as not relevant; a CVE listed in CISA KEV is never dismissed automatically. "+
			"In this period: %d decisions made, %d revoked, %d per-server human decisions.",
		modeText, active, r.Created, r.Revoked, r.OverridesTotal), props.Text{Size: 8.5, Top: 1})))
	m.AddRow(4, col.New(12))

	// Per-rule table
	m.AddRow(8,
		col.New(4).Add(h("Rule", 8, align.Left)),
		col.New(1).Add(h("Applied", 8, align.Center)),
		col.New(1).Add(h("Shadow", 8, align.Center)),
		col.New(1).Add(h("Blocked", 8, align.Center)),
		col.New(2).Add(h("Overridden by human", 8, align.Center)),
		col.New(3).Add(h("Human: not relevant / accepted risk / relevant", 8, align.Center)),
	).WithStyle(headerCell)
	if len(r.Rules) == 0 {
		m.AddRow(7, col.New(12).Add(c("No automated decisions for the servers in scope.", 8, align.Left))).WithStyle(rowCell(0))
	}
	for i, rr := range r.Rules {
		label := rr.RuleID
		if rr.Description != "" {
			label += " — " + rr.Description
		}
		m.AddAutoRow(
			col.New(4).Add(text.New(label, props.Text{Size: 7.5, Top: 1.5, Bottom: 1.5})),
			col.New(1).Add(c(fmt.Sprint(rr.Applied), 8, align.Center)),
			col.New(1).Add(c(fmt.Sprint(rr.Shadow), 8, align.Center)),
			col.New(1).Add(c(fmt.Sprint(rr.Blocked), 8, align.Center)),
			col.New(2).Add(c(fmt.Sprint(rr.Overridden), 8, align.Center)),
			col.New(3).Add(c(fmt.Sprintf("%d / %d / %d", rr.HumanAgree, rr.HumanAccepted, rr.HumanDisagree), 8, align.Center)),
		).WithStyle(rowCell(i))
	}
	m.AddRow(5, col.New(12).Add(text.New(
		"Applied: in effect. Shadow: computed, not in effect. Blocked: a guard (CISA KEV, verified exploit, EPSS threshold) prevents it. "+
			"Human: how a human assessed the same server. Accepted risk does not contradict the dismissal; relevant does.",
		props.Text{Size: 6.5, Color: grey, Top: 1})))
	m.AddRow(6, col.New(12))

	// Dismissed CVEs
	if r.DismissedTotal > 0 {
		title := fmt.Sprintf("CVEs dismissed automatically (%d)", r.DismissedTotal)
		if r.DismissedTotal > len(r.Dismissed) {
			title += fmt.Sprintf(", top %d by servers", len(r.Dismissed))
		}
		m.AddRow(8, col.New(12).Add(text.New(title, props.Text{Size: 10, Style: fontstyle.Bold})))
		m.AddRow(8,
			col.New(4).Add(h("CVE ID", 8, align.Left)),
			col.New(2).Add(h("Servers", 8, align.Center)),
			col.New(6).Add(h("Rules", 8, align.Left)),
		).WithStyle(headerCell)
		for i, d := range r.Dismissed {
			m.AddRow(7,
				col.New(4).Add(c(d.CVEID, 8, align.Left)),
				col.New(2).Add(c(fmt.Sprint(d.Servers), 8, align.Center)),
				col.New(6).Add(c(d.Rules, 8, align.Left)),
			).WithStyle(rowCell(i))
		}
		m.AddRow(6, col.New(12))
	}

	// Human decisions per server
	if r.OverridesTotal > 0 {
		title := fmt.Sprintf("Per-server human decisions in this period (%d)", r.OverridesTotal)
		if r.OverridesTotal > len(r.Overrides) {
			title += fmt.Sprintf(", newest %d", len(r.Overrides))
		}
		m.AddRow(8, col.New(12).Add(text.New(title, props.Text{Size: 10, Style: fontstyle.Bold})))
		m.AddRow(8,
			col.New(2).Add(h("Date", 8, align.Left)),
			col.New(2).Add(h("Server", 8, align.Left)),
			col.New(2).Add(h("CVE ID", 8, align.Left)),
			col.New(2).Add(h("Decision", 8, align.Left)),
			col.New(4).Add(h("By / comment", 8, align.Left)),
		).WithStyle(headerCell)
		for i, o := range r.Overrides {
			by := o.Actor
			if o.Comment != "" {
				if by != "" {
					by += ": "
				}
				by += o.Comment
			}
			m.AddAutoRow(
				col.New(2).Add(c(o.At.Format("2006-01-02"), 7.5, align.Left)),
				col.New(2).Add(c(o.Server, 7.5, align.Left)),
				col.New(2).Add(c(o.CVEID, 7.5, align.Left)),
				col.New(2).Add(c(strings.ReplaceAll(o.Status, "_", " "), 7.5, align.Left)),
				col.New(4).Add(text.New(by, props.Text{Size: 7.5, Top: 1.5, Bottom: 1.5})),
			).WithStyle(rowCell(i))
		}
	}
	m.AddRow(10, col.New(12))
}
