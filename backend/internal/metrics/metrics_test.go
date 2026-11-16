package metrics

// The DB collector against a throwaway PostgreSQL: the cached metrics are
// present on the first scrape and survive a refresh that fails.
//
// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/vultrack/vultrack/internal/testdb"
)

func TestHeavyMetricsCache(t *testing.T) {
	pool, _ := testdb.Setup(t, "metrics_tests")
	backlog, fail := 7, false
	PreconditionBacklog = func(ctx context.Context) (int, error) {
		if fail {
			return 0, context.DeadlineExceeded
		}
		return backlog, nil
	}
	t.Cleanup(func() { PreconditionBacklog = nil })

	c := NewDBCollector(pool)
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	value := func() (float64, bool) {
		t.Helper()
		mfs, err := reg.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, mf := range mfs {
			if mf.GetName() == "vultrack_ai_preconditions_backlog" {
				return mf.GetMetric()[0].GetGauge().GetValue(), true
			}
		}
		return 0, false
	}
	if v, ok := value(); !ok || v != 7 {
		t.Fatalf("first scrape: backlog %v (present %v), want 7", v, ok)
	}

	// A failing refresh keeps the previous value.
	fail = true
	c.heavyMu.Lock()
	c.heavyAt = c.heavyAt.Add(-2 * heavyMetricsTTL)
	c.heavyMu.Unlock()
	value() // starts the refresh
	waitRefresh(c)
	if v, ok := value(); !ok || v != 7 {
		t.Errorf("after a failed refresh: backlog %v (present %v), want 7", v, ok)
	}

	// A successful refresh updates it.
	fail, backlog = false, 9
	c.heavyMu.Lock()
	c.heavyAt = c.heavyAt.Add(-2 * heavyMetricsTTL)
	c.heavyMu.Unlock()
	value()
	waitRefresh(c)
	if v, _ := value(); v != 9 {
		t.Errorf("after a refresh: backlog %v, want 9", v)
	}
}

func waitRefresh(c *DBCollector) {
	c.heavyMu.Lock()
	done := c.heavyDone
	c.heavyMu.Unlock()
	if done != nil {
		<-done
	}
}
