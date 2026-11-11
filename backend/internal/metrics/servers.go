package metrics

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/vultrack/vultrack/internal/services"
)

var (
	serverLastReport = prometheus.NewDesc("vultrack_server_last_report_timestamp",
		"Unix time of the last agent report per enabled server. Alert with e.g. time() - vultrack_server_last_report_timestamp > 86400.",
		[]string{"server"}, nil)
	serversStale = prometheus.NewDesc("vultrack_servers_stale",
		"Enabled servers without an agent report for longer than the configured threshold (0 when warnings are off).", nil, nil)
	serversDisabled = prometheus.NewDesc("vultrack_servers_disabled",
		"Servers marked as disabled (switched off, kept in VulTrack).", nil, nil)
)

func describeServers(ch chan<- *prometheus.Desc) {
	ch <- serverLastReport
	ch <- serversStale
	ch <- serversDisabled
}

func (c *DBCollector) collectServerReports(ctx context.Context, ch chan<- prometheus.Metric) {
	// Age by the database clock, so a timestamp column without time zone
	// cannot shift the result.
	rows, err := c.db.Query(ctx, `
		SELECT name, EXTRACT(EPOCH FROM NOW())::float8 - EXTRACT(EPOCH FROM NOW() - COALESCE(last_report_at, created_at))::float8
		FROM servers WHERE disabled_at IS NULL
	`)
	if err == nil {
		for rows.Next() {
			var name string
			var ts float64
			if rows.Scan(&name, &ts) == nil {
				ch <- prometheus.MustNewConstMetric(serverLastReport, prometheus.GaugeValue, ts, name)
			}
		}
		rows.Close()
	}
	var disabled int64
	if c.db.QueryRow(ctx, `SELECT COUNT(*) FROM servers WHERE disabled_at IS NOT NULL`).Scan(&disabled) == nil {
		ch <- prometheus.MustNewConstMetric(serversDisabled, prometheus.GaugeValue, float64(disabled))
	}
	cfg, err := services.NewSettingsService(c.db).LoadStaleConfig(ctx)
	if err != nil {
		return
	}
	stale := 0
	if cfg.Hours > 0 {
		list, err := services.NewServerService(c.db).StaleServers(ctx, cfg.Threshold())
		if err != nil {
			return
		}
		stale = len(list)
	}
	ch <- prometheus.MustNewConstMetric(serversStale, prometheus.GaugeValue, float64(stale))
}
