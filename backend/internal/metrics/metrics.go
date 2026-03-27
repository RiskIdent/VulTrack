package metrics

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// In-memory metrics — updated at event time.
var (
	ScanJobsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vultrack_scan_jobs_total",
		Help: "Total number of completed scan jobs by final status and trigger type.",
	}, []string{"status", "trigger"})

	ScanDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vultrack_scan_duration_seconds",
		Help:    "Duration of completed scan jobs in seconds.",
		Buckets: []float64{1, 5, 10, 30, 60, 120, 300},
	}, []string{"trigger"})

	AgentAuthFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vultrack_agent_auth_failures_total",
		Help: "Total number of JWT authentication failures from agents.",
	})

	AgentReportsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vultrack_agent_reports_total",
		Help: "Total number of agent reports received.",
	})
)

// DBCollector implements prometheus.Collector for metrics derived from the database.
// It is called on every Prometheus scrape.
type DBCollector struct {
	db *pgxpool.Pool

	findingsActive  *prometheus.Desc
	assessments     *prometheus.Desc
	serversTotal    *prometheus.Desc
	agentsTotal     *prometheus.Desc
	scanJobsWaiting *prometheus.Desc
	scanJobsRunning *prometheus.Desc
	syncLastSuccess *prometheus.Desc
}

func NewDBCollector(db *pgxpool.Pool) *DBCollector {
	return &DBCollector{
		db: db,
		findingsActive: prometheus.NewDesc(
			"vultrack_findings_active_total",
			"Number of active (unresolved) findings by severity.",
			[]string{"severity"}, nil,
		),
		assessments: prometheus.NewDesc(
			"vultrack_assessments_total",
			"Number of unique CVEs with active findings by assessment status.",
			[]string{"status"}, nil,
		),
		serversTotal: prometheus.NewDesc(
			"vultrack_servers_total",
			"Total number of registered servers.",
			nil, nil,
		),
		agentsTotal: prometheus.NewDesc(
			"vultrack_agents_total",
			"Number of agents by status.",
			[]string{"status"}, nil,
		),
		scanJobsWaiting: prometheus.NewDesc(
			"vultrack_scan_jobs_waiting",
			"Number of scan jobs currently waiting in the queue.",
			nil, nil,
		),
		scanJobsRunning: prometheus.NewDesc(
			"vultrack_scan_jobs_running",
			"Number of scan jobs currently running.",
			nil, nil,
		),
		syncLastSuccess: prometheus.NewDesc(
			"vultrack_sync_last_success_timestamp",
			"Unix timestamp of the last successful data sync by source.",
			[]string{"source"}, nil,
		),
	}
}

func (c *DBCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.findingsActive
	ch <- c.assessments
	ch <- c.serversTotal
	ch <- c.agentsTotal
	ch <- c.scanJobsWaiting
	ch <- c.scanJobsRunning
	ch <- c.syncLastSuccess
}

func (c *DBCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c.collectFindings(ctx, ch)
	c.collectAssessments(ctx, ch)
	c.collectServers(ctx, ch)
	c.collectAgents(ctx, ch)
	c.collectScanJobs(ctx, ch)
	c.collectSyncTimestamps(ctx, ch)
}

func (c *DBCollector) collectFindings(ctx context.Context, ch chan<- prometheus.Metric) {
	rows, err := c.db.Query(ctx, `
		SELECT COALESCE(LOWER(severity), 'unknown'), COUNT(*)
		FROM findings
		WHERE resolved_at IS NULL
		GROUP BY LOWER(severity)
	`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var severity string
		var count float64
		if rows.Scan(&severity, &count) == nil {
			ch <- prometheus.MustNewConstMetric(c.findingsActive, prometheus.GaugeValue, count, severity)
		}
	}
}

func (c *DBCollector) collectAssessments(ctx context.Context, ch chan<- prometheus.Metric) {
	rows, err := c.db.Query(ctx, `
		SELECT COALESCE(a.status, 'pending'), COUNT(DISTINCT f.cve_id)
		FROM findings f
		LEFT JOIN assessments a ON f.cve_id = a.cve_id
		WHERE f.resolved_at IS NULL
		GROUP BY a.status
	`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count float64
		if rows.Scan(&status, &count) == nil {
			ch <- prometheus.MustNewConstMetric(c.assessments, prometheus.GaugeValue, count, status)
		}
	}
}

func (c *DBCollector) collectServers(ctx context.Context, ch chan<- prometheus.Metric) {
	var count float64
	if c.db.QueryRow(ctx, `SELECT COUNT(*) FROM servers`).Scan(&count) == nil {
		ch <- prometheus.MustNewConstMetric(c.serversTotal, prometheus.GaugeValue, count)
	}
}

func (c *DBCollector) collectAgents(ctx context.Context, ch chan<- prometheus.Metric) {
	rows, err := c.db.Query(ctx, `SELECT status, COUNT(*) FROM registered_agents GROUP BY status`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count float64
		if rows.Scan(&status, &count) == nil {
			ch <- prometheus.MustNewConstMetric(c.agentsTotal, prometheus.GaugeValue, count, status)
		}
	}
}

func (c *DBCollector) collectScanJobs(ctx context.Context, ch chan<- prometheus.Metric) {
	rows, err := c.db.Query(ctx, `
		SELECT status, COUNT(*)
		FROM scan_jobs
		WHERE status IN ('queued', 'running')
		GROUP BY status
	`)
	if err != nil {
		return
	}
	defer rows.Close()
	waiting, running := 0.0, 0.0
	for rows.Next() {
		var status string
		var count float64
		if rows.Scan(&status, &count) == nil {
			switch status {
			case "queued":
				waiting = count
			case "running":
				running = count
			}
		}
	}
	ch <- prometheus.MustNewConstMetric(c.scanJobsWaiting, prometheus.GaugeValue, waiting)
	ch <- prometheus.MustNewConstMetric(c.scanJobsRunning, prometheus.GaugeValue, running)
}

func (c *DBCollector) collectSyncTimestamps(ctx context.Context, ch chan<- prometheus.Metric) {
	// NVD and ExploitDB from the shared sync_status table
	rows, err := c.db.Query(ctx, `
		SELECT source_type, last_sync_at
		FROM sync_status
		WHERE status = 'success' AND source_type IN ('nvd', 'exploitdb')
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var source string
			var t time.Time
			if rows.Scan(&source, &t) == nil {
				ch <- prometheus.MustNewConstMetric(c.syncLastSuccess, prometheus.GaugeValue, float64(t.Unix()), source)
			}
		}
	}

	// OVAL: aggregate across all sources
	var ovalT *time.Time
	if c.db.QueryRow(ctx, `
		SELECT MAX(last_sync_at) FROM oval_sources WHERE sync_status = 'success'
	`).Scan(&ovalT) == nil && ovalT != nil {
		ch <- prometheus.MustNewConstMetric(c.syncLastSuccess, prometheus.GaugeValue, float64(ovalT.Unix()), "oval")
	}
}
