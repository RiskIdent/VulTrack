package nvd

// Same parameter-typing trap as in the VEX syncer, and the same silent failure
// mode: updateSyncStatus only logs. The NVD row is additionally written by
// saveChunkProgress, so before the fix the row existed but was stuck on
// 'syncing' forever and never got a last_sync_at.
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

func setupNVDSyncer(t *testing.T) (*Syncer, *pgxpool.Pool, context.Context) {
	t.Helper()
	pool, ctx := testdb.Setup(t, "nvd_tests")
	return New(pool, services.NewSettingsService(pool)), pool, ctx
}

func readNVDStatus(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (status string, lastSync, syncedUntil *time.Time, records int) {
	t.Helper()
	err := pool.QueryRow(ctx, `
		SELECT COALESCE(status, ''), last_sync_at, synced_until, COALESCE(records_processed, 0)
		FROM sync_status WHERE source_type = 'nvd' AND source_name = 'nvd'
	`).Scan(&status, &lastSync, &syncedUntil, &records)
	if err != nil {
		t.Fatalf("no nvd sync status row: %v", err)
	}
	return
}

// TestNVDSyncStatusReachesTerminalState covers what the bug broke: the row got
// stuck on 'syncing' because only saveChunkProgress could write it.
func TestNVDSyncStatusReachesTerminalState(t *testing.T) {
	syncer, pool, ctx := setupNVDSyncer(t)

	// A chunk completes mid-sync: the resume cursor advances, no success yet.
	cursor := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	syncer.saveChunkProgress(ctx, cursor, 500)

	status, lastSync, syncedUntil, records := readNVDStatus(t, ctx, pool)
	if status != "syncing" || records != 500 {
		t.Errorf("got status %q with %d records, want \"syncing\" with 500", status, records)
	}
	if lastSync != nil {
		t.Errorf("last_sync_at was set before any sync succeeded: %v", lastSync)
	}
	if syncedUntil == nil || !syncedUntil.Equal(cursor) {
		t.Errorf("synced_until = %v, want %v", syncedUntil, cursor)
	}

	// The sync finishes. Both timestamps advance.
	syncer.updateSyncStatus(ctx, "success", "", 1200)
	status, lastSync, syncedUntil, records = readNVDStatus(t, ctx, pool)
	if status != "success" || records != 1200 {
		t.Errorf("got status %q with %d records, want \"success\" with 1200", status, records)
	}
	if lastSync == nil {
		t.Fatal("last_sync_at was not set on success")
	}
	if syncedUntil == nil || !syncedUntil.After(cursor) {
		t.Errorf("synced_until did not advance on success: %v", syncedUntil)
	}
	succeededAt, cursorAt := *lastSync, *syncedUntil

	// A later run fails. Both the success timestamp and the resume cursor are
	// preserved, so the next run picks up where this one stopped.
	syncer.updateSyncStatus(ctx, "failed", "rate limited", 30)
	status, lastSync, syncedUntil, _ = readNVDStatus(t, ctx, pool)
	if status != "failed" {
		t.Errorf("status = %q, want \"failed\"", status)
	}
	if lastSync == nil || !lastSync.Equal(succeededAt) {
		t.Errorf("last_sync_at changed on failure: %v, want %v", lastSync, succeededAt)
	}
	if syncedUntil == nil || !syncedUntil.Equal(cursorAt) {
		t.Errorf("synced_until changed on failure: %v, want %v", syncedUntil, cursorAt)
	}
}
