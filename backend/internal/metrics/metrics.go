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

	// pgxpool client-side stats
	dbPoolTotal              *prometheus.Desc
	dbPoolIdle               *prometheus.Desc
	dbPoolAcquired           *prometheus.Desc
	dbPoolMax                *prometheus.Desc
	dbPoolAcquireCount       *prometheus.Desc
	dbPoolEmptyAcquireCount  *prometheus.Desc
	dbPoolCanceledAcquireCnt *prometheus.Desc
	dbPoolNewConnsCount      *prometheus.Desc

	// PostgreSQL server-side stats (pg_stat_database for current DB)
	dbSizeBytes      *prometheus.Desc
	dbConnections    *prometheus.Desc
	dbTransactions   *prometheus.Desc
	dbBlocks         *prometheus.Desc
	dbDeadlocksTotal *prometheus.Desc
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

		dbPoolTotal: prometheus.NewDesc(
			"vultrack_db_pool_conns_total",
			"Total connections currently held by the pgx connection pool.",
			nil, nil,
		),
		dbPoolIdle: prometheus.NewDesc(
			"vultrack_db_pool_conns_idle",
			"Idle connections in the pgx connection pool.",
			nil, nil,
		),
		dbPoolAcquired: prometheus.NewDesc(
			"vultrack_db_pool_conns_acquired",
			"Connections currently acquired (in use) from the pgx connection pool.",
			nil, nil,
		),
		dbPoolMax: prometheus.NewDesc(
			"vultrack_db_pool_conns_max",
			"Configured maximum connections of the pgx connection pool.",
			nil, nil,
		),
		dbPoolAcquireCount: prometheus.NewDesc(
			"vultrack_db_pool_acquire_total",
			"Cumulative successful connection acquires from the pgx pool.",
			nil, nil,
		),
		dbPoolEmptyAcquireCount: prometheus.NewDesc(
			"vultrack_db_pool_empty_acquire_total",
			"Cumulative acquires that had to wait because the pool was empty (saturation indicator).",
			nil, nil,
		),
		dbPoolCanceledAcquireCnt: prometheus.NewDesc(
			"vultrack_db_pool_canceled_acquire_total",
			"Cumulative acquires cancelled before completion (e.g. context deadline).",
			nil, nil,
		),
		dbPoolNewConnsCount: prometheus.NewDesc(
			"vultrack_db_pool_new_conns_total",
			"Cumulative new physical connections opened by the pgx pool.",
			nil, nil,
		),

		dbSizeBytes: prometheus.NewDesc(
			"vultrack_db_size_bytes",
			"On-disk size of the application database in bytes.",
			nil, nil,
		),
		dbConnections: prometheus.NewDesc(
			"vultrack_db_backends",
			"Number of backends currently connected to the application database (pg_stat_database.numbackends).",
			nil, nil,
		),
		dbTransactions: prometheus.NewDesc(
			"vultrack_db_transactions_total",
			"Cumulative transactions on the application database, by result (commit/rollback).",
			[]string{"result"}, nil,
		),
		dbBlocks: prometheus.NewDesc(
			"vultrack_db_blocks_total",
			"Cumulative disk blocks accessed on the application database, by source (read=from disk, hit=from cache).",
			[]string{"type"}, nil,
		),
		dbDeadlocksTotal: prometheus.NewDesc(
			"vultrack_db_deadlocks_total",
			"Cumulative deadlocks detected on the application database.",
			nil, nil,
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
	ch <- c.dbPoolTotal
	ch <- c.dbPoolIdle
	ch <- c.dbPoolAcquired
	ch <- c.dbPoolMax
	ch <- c.dbPoolAcquireCount
	ch <- c.dbPoolEmptyAcquireCount
	ch <- c.dbPoolCanceledAcquireCnt
	ch <- c.dbPoolNewConnsCount
	ch <- c.dbSizeBytes
	ch <- c.dbConnections
	ch <- c.dbTransactions
	ch <- c.dbBlocks
	ch <- c.dbDeadlocksTotal
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
	c.collectPoolStats(ch)
	c.collectPostgresStats(ctx, ch)
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
	// NVD, ExploitDB and VEX from the shared sync_status table
	rows, err := c.db.Query(ctx, `
		SELECT source_type, last_sync_at
		FROM sync_status
		WHERE status = 'success' AND source_type IN ('nvd', 'exploitdb', 'vex')
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

// collectPoolStats reports pgxpool client-side counters and gauges. No DB query.
func (c *DBCollector) collectPoolStats(ch chan<- prometheus.Metric) {
	s := c.db.Stat()
	ch <- prometheus.MustNewConstMetric(c.dbPoolTotal, prometheus.GaugeValue, float64(s.TotalConns()))
	ch <- prometheus.MustNewConstMetric(c.dbPoolIdle, prometheus.GaugeValue, float64(s.IdleConns()))
	ch <- prometheus.MustNewConstMetric(c.dbPoolAcquired, prometheus.GaugeValue, float64(s.AcquiredConns()))
	ch <- prometheus.MustNewConstMetric(c.dbPoolMax, prometheus.GaugeValue, float64(s.MaxConns()))
	ch <- prometheus.MustNewConstMetric(c.dbPoolAcquireCount, prometheus.CounterValue, float64(s.AcquireCount()))
	ch <- prometheus.MustNewConstMetric(c.dbPoolEmptyAcquireCount, prometheus.CounterValue, float64(s.EmptyAcquireCount()))
	ch <- prometheus.MustNewConstMetric(c.dbPoolCanceledAcquireCnt, prometheus.CounterValue, float64(s.CanceledAcquireCount()))
	ch <- prometheus.MustNewConstMetric(c.dbPoolNewConnsCount, prometheus.CounterValue, float64(s.NewConnsCount()))
}

// collectPostgresStats reports server-side stats for the current database from pg_stat_database.
func (c *DBCollector) collectPostgresStats(ctx context.Context, ch chan<- prometheus.Metric) {
	var (
		numbackends                    int64
		xactCommit, xactRollback       int64
		blksRead, blksHit              int64
		deadlocks                      int64
		dbSize                         int64
	)
	err := c.db.QueryRow(ctx, `
		SELECT
		    numbackends,
		    xact_commit,
		    xact_rollback,
		    blks_read,
		    blks_hit,
		    deadlocks,
		    pg_database_size(datname)
		FROM pg_stat_database
		WHERE datname = current_database()
	`).Scan(&numbackends, &xactCommit, &xactRollback, &blksRead, &blksHit, &deadlocks, &dbSize)
	if err != nil {
		return
	}

	ch <- prometheus.MustNewConstMetric(c.dbSizeBytes, prometheus.GaugeValue, float64(dbSize))
	ch <- prometheus.MustNewConstMetric(c.dbConnections, prometheus.GaugeValue, float64(numbackends))
	ch <- prometheus.MustNewConstMetric(c.dbTransactions, prometheus.CounterValue, float64(xactCommit), "commit")
	ch <- prometheus.MustNewConstMetric(c.dbTransactions, prometheus.CounterValue, float64(xactRollback), "rollback")
	ch <- prometheus.MustNewConstMetric(c.dbBlocks, prometheus.CounterValue, float64(blksRead), "read")
	ch <- prometheus.MustNewConstMetric(c.dbBlocks, prometheus.CounterValue, float64(blksHit), "hit")
	ch <- prometheus.MustNewConstMetric(c.dbDeadlocksTotal, prometheus.CounterValue, float64(deadlocks))
}
