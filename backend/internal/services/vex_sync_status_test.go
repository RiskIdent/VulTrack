package services_test

// The sync status upsert reuses one parameter both as a column value and inside
// a comparison, which Postgres rejects unless the parameter's type is pinned.
// Both callers only log the failure, so nothing surfaced it until the server
// logs were read: the status row simply never appeared. These tests assert the
// effect rather than an error return.
//
// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

// syncStatusRow is what the admin UI and the Prometheus metric read.
type syncStatusRow struct {
	Status           string
	LastSyncAt       *time.Time
	ErrorMessage     string
	RecordsProcessed int
}

func setupSyncStatusDB(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	return testdb.Setup(t, "service_tests")
}

func readSyncStatus(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sourceType string) *syncStatusRow {
	t.Helper()

	var row syncStatusRow
	var errMsg *string
	err := pool.QueryRow(ctx, `
		SELECT COALESCE(status, ''), last_sync_at, error_message, COALESCE(records_processed, 0)
		FROM sync_status WHERE source_type = $1 AND source_name = $1
	`, sourceType).Scan(&row.Status, &row.LastSyncAt, &errMsg, &row.RecordsProcessed)
	if err != nil {
		t.Fatalf("no %s sync status row: %v", sourceType, err)
	}
	if errMsg != nil {
		row.ErrorMessage = *errMsg
	}
	return &row
}

// TestVEXSyncStatusLifecycle walks the three states the syncer reports and
// checks that last_sync_at only ever means "last successful sync".
func TestVEXSyncStatusLifecycle(t *testing.T) {
	pool, ctx := setupSyncStatusDB(t)
	vexService := services.NewVEXService(pool)

	// A sync starts. The row has to exist even though nothing succeeded yet.
	vexService.UpdateSyncStatus(ctx, "syncing", "", 0)
	row := readSyncStatus(t, ctx, pool, "vex")
	if row.Status != "syncing" {
		t.Errorf("status = %q, want \"syncing\"", row.Status)
	}
	if row.LastSyncAt != nil {
		t.Errorf("last_sync_at was set before any sync succeeded: %v", row.LastSyncAt)
	}

	// It succeeds.
	vexService.UpdateSyncStatus(ctx, "success", "", 4711)
	row = readSyncStatus(t, ctx, pool, "vex")
	if row.Status != "success" || row.RecordsProcessed != 4711 {
		t.Errorf("got status %q with %d records, want \"success\" with 4711", row.Status, row.RecordsProcessed)
	}
	if row.LastSyncAt == nil {
		t.Fatal("last_sync_at was not set on success")
	}
	succeededAt := *row.LastSyncAt

	// A later run fails. The success timestamp must survive, because that is
	// what the admin UI and sync_last_success report.
	vexService.UpdateSyncStatus(ctx, "failed", "download failed", 12)
	row = readSyncStatus(t, ctx, pool, "vex")
	if row.Status != "failed" || row.ErrorMessage != "download failed" {
		t.Errorf("got status %q with error %q, want \"failed\" with the message", row.Status, row.ErrorMessage)
	}
	if row.LastSyncAt == nil || !row.LastSyncAt.Equal(succeededAt) {
		t.Errorf("last_sync_at changed on failure: %v, want %v", row.LastSyncAt, succeededAt)
	}
}
