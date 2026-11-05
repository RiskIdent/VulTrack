package metrics

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/vultrack/vultrack/internal/services"
)

// Metrics of the assessment automation that are not decision counts: AI cost
// and progress, kernel data for R-KMOD and runtime facts coverage. They read
// small tables only and are computed on every scrape.
var (
	aiCalls = prometheus.NewDesc("vultrack_ai_calls_total",
		"Model calls that consumed tokens, by AI stage (advisory, preconditions), model and batch (true = Message Batches API).",
		[]string{"stage", "model", "batch"}, nil)
	aiTokens = prometheus.NewDesc("vultrack_ai_tokens_total",
		"Tokens consumed, by AI stage, model and type (input, output, cache_read, cache_write).",
		[]string{"stage", "model", "type"}, nil)
	aiCost = prometheus.NewDesc("vultrack_ai_cost_usd_total",
		"Estimated cost in USD at Anthropic list prices, by AI stage and model.",
		[]string{"stage", "model"}, nil)
	aiCostMonth = prometheus.NewDesc("vultrack_ai_cost_month_usd",
		"Estimated cost in USD in the current calendar month, by AI stage.",
		[]string{"stage"}, nil)
	preBudget = prometheus.NewDesc("vultrack_ai_preconditions_budget_usd",
		"Monthly budget of the AI precondition analysis in USD.", nil, nil)
	preEnabled = prometheus.NewDesc("vultrack_ai_preconditions_enabled",
		"1 when the AI precondition analysis is enabled.", nil, nil)
	preAnalyses = prometheus.NewDesc("vultrack_ai_preconditions_analyses",
		"Stored precondition analyses by state: ok, determinable (subset of ok), pending (in a batch), error, "+
			"refused (declined by the main model), by_fallback (ok, made by the fallback model after a refusal).",
		[]string{"state"}, nil)
	preBatches = prometheus.NewDesc("vultrack_ai_preconditions_batches_in_progress",
		"Message Batches of the precondition analysis still processing.", nil, nil)
	autoMode = prometheus.NewDesc("vultrack_auto_assessment_mode",
		"1 for the configured global mode of the automated assessment (off, shadow, active).", []string{"mode"}, nil)
	ruleMode = prometheus.NewDesc("vultrack_auto_assessment_rule_mode",
		"1 for the effective mode of each rule (off, shadow, active).", []string{"rule", "mode"}, nil)
	kernelCVEs = prometheus.NewDesc("vultrack_kernel_cve_records",
		"Kernel CVE records fetched for R-KMOD by status (ok, no_files, not_found, error).", []string{"status"}, nil)
	kernelBuilds = prometheus.NewDesc("vultrack_kernel_builds",
		"Kernel builds mapped for R-KMOD by status (ok, error).", []string{"status"}, nil)
	runtimeServers = prometheus.NewDesc("vultrack_runtime_fact_servers",
		"Servers with current runtime facts per category (complete = not truncated).", []string{"category", "complete"}, nil)
	usageObserved = prometheus.NewDesc("vultrack_package_usage_observed_servers",
		"Servers whose package usage is currently observed without a gap.", nil, nil)
)

// RuleIDs lists the rules for the mode metric; set by main to avoid an import
// cycle with internal/autoassess.
var RuleIDs []string

func describeAutomation(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{aiCalls, aiTokens, aiCost, aiCostMonth, preBudget, preEnabled, preAnalyses, preBatches,
		autoMode, ruleMode, kernelCVEs, kernelBuilds, runtimeServers, usageObserved} {
		ch <- d
	}
}

func (c *DBCollector) collectAutomation(ctx context.Context, ch chan<- prometheus.Metric) {
	gauge := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...)
	}
	counter := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, v, labels...)
	}

	if rows, err := c.db.Query(ctx, `
		SELECT stage, model, batch, COUNT(*), SUM(input_tokens), SUM(output_tokens), SUM(cache_read_tokens),
		       SUM(cache_creation_tokens), SUM(cost_usd)::float8
		FROM ai_usage GROUP BY 1, 2, 3
	`); err == nil {
		costs := map[[2]string]float64{}
		tokens := map[[3]string]float64{}
		for rows.Next() {
			var stage, model string
			var batch bool
			var n, in, out, cr, cw int64
			var cost float64
			if rows.Scan(&stage, &model, &batch, &n, &in, &out, &cr, &cw, &cost) != nil {
				continue
			}
			b := "false"
			if batch {
				b = "true"
			}
			counter(aiCalls, float64(n), stage, model, b)
			costs[[2]string{stage, model}] += cost
			for typ, v := range map[string]int64{"input": in, "output": out, "cache_read": cr, "cache_write": cw} {
				tokens[[3]string{stage, model, typ}] += float64(v)
			}
		}
		rows.Close()
		for k, v := range costs {
			counter(aiCost, v, k[0], k[1])
		}
		for k, v := range tokens {
			counter(aiTokens, v, k[0], k[1], k[2])
		}
	}
	if rows, err := c.db.Query(ctx, `
		SELECT stage, SUM(cost_usd)::float8 FROM ai_usage WHERE created_at >= date_trunc('month', NOW()) GROUP BY 1
	`); err == nil {
		for rows.Next() {
			var stage string
			var cost float64
			if rows.Scan(&stage, &cost) == nil {
				gauge(aiCostMonth, cost, stage)
			}
		}
		rows.Close()
	}

	settings := services.NewSettingsService(c.db)
	if pc, err := settings.LoadPreconditionConfig(ctx); err == nil {
		gauge(preBudget, pc.BudgetUSD)
		enabled := 0.0
		if pc.Enabled {
			enabled = 1
		}
		gauge(preEnabled, enabled)
	}
	var ok, det, pending, errs, refused, fallback, batches int64
	if c.db.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE status = 'ok'), COUNT(*) FILTER (WHERE status = 'ok' AND determinable),
		       COUNT(*) FILTER (WHERE status = 'pending'), COUNT(*) FILTER (WHERE status = 'error'),
		       COUNT(*) FILTER (WHERE refused_by IS NOT NULL), COUNT(*) FILTER (WHERE status = 'ok' AND refused_by IS NOT NULL),
		       (SELECT COUNT(*) FROM precondition_batches WHERE status = 'in_progress')
		FROM precondition_analyses
	`).Scan(&ok, &det, &pending, &errs, &refused, &fallback, &batches) == nil {
		for state, v := range map[string]int64{"ok": ok, "determinable": det, "pending": pending, "error": errs,
			"refused": refused, "by_fallback": fallback} {
			gauge(preAnalyses, float64(v), state)
		}
		gauge(preBatches, float64(batches))
	}

	if cfg, err := settings.LoadAutoAssessmentConfig(ctx); err == nil {
		for _, m := range []string{services.AutoModeOff, services.AutoModeShadow, services.AutoModeActive} {
			v := 0.0
			if cfg.Mode == m {
				v = 1
			}
			gauge(autoMode, v, m)
		}
		for _, id := range RuleIDs {
			gauge(ruleMode, 1, id, cfg.RuleMode(id))
		}
	}

	for _, q := range []struct {
		d   *prometheus.Desc
		sql string
	}{
		{kernelCVEs, `SELECT status, COUNT(*) FROM kernel_cve_files GROUP BY 1`},
		{kernelBuilds, `SELECT status, COUNT(*) FROM kernel_builds GROUP BY 1`},
	} {
		if rows, err := c.db.Query(ctx, q.sql); err == nil {
			for rows.Next() {
				var status string
				var n int64
				if rows.Scan(&status, &n) == nil {
					gauge(q.d, float64(n), status)
				}
			}
			rows.Close()
		}
	}
	if rows, err := c.db.Query(ctx, `SELECT category, NOT truncated, COUNT(*) FROM server_facts GROUP BY 1, 2`); err == nil {
		for rows.Next() {
			var cat string
			var complete bool
			var n int64
			if rows.Scan(&cat, &complete, &n) == nil {
				cs := "false"
				if complete {
					cs = "true"
				}
				gauge(runtimeServers, float64(n), cat, cs)
			}
		}
		rows.Close()
	}
	var observed int64
	if c.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM package_usage_observation
		WHERE observed_since IS NOT NULL AND last_observed_at >= NOW() - make_interval(secs => $1)
	`, services.UsageGap.Seconds()).Scan(&observed) == nil {
		gauge(usageObserved, float64(observed))
	}
}
