package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/models"
)

// VEXService handles database operations for Ubuntu VEX statements.
type VEXService struct {
	db *pgxpool.Pool
}

// NewVEXService creates a new VEXService.
func NewVEXService(db *pgxpool.Pool) *VEXService {
	return &VEXService{db: db}
}

// VEXRow is a normalised row ready for bulk insert.
// Kept here to avoid a circular import with the vex package.
type VEXRow struct {
	CVEID         string
	PackageName   string
	Distro        string
	Status        string
	Justification string
	SourceType    string
	SourceID      string
}

// BulkInsert upserts a batch of VEX rows with the given sync generation.
// Returns the number of rows written.
func (s *VEXService) BulkInsert(ctx context.Context, rows []VEXRow, generation int) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	// Build multi-row VALUES clause.
	placeholders := make([]string, 0, len(rows))
	args := make([]interface{}, 0, len(rows)*8)
	idx := 1

	for _, r := range rows {
		placeholders = append(placeholders, fmt.Sprintf(
			"($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			idx, idx+1, idx+2, idx+3, idx+4, idx+5, idx+6, idx+7,
		))
		args = append(args,
			r.CVEID, r.PackageName, r.Distro, r.Status,
			r.Justification, r.SourceType, r.SourceID, generation,
		)
		idx += 8
	}

	query := `
		INSERT INTO vex_statements
			(cve_id, package_name, distro, status, justification, source_type, source_id, sync_generation)
		VALUES ` + strings.Join(placeholders, ",") + `
		ON CONFLICT (cve_id, package_name, distro, source_type) DO UPDATE SET
			status          = EXCLUDED.status,
			justification   = EXCLUDED.justification,
			source_id       = EXCLUDED.source_id,
			sync_generation = EXCLUDED.sync_generation`

	tag, err := s.db.Exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// GetCurrentGeneration returns the highest sync_generation present in the table
// (0 if the table is empty).
func (s *VEXService) GetCurrentGeneration(ctx context.Context) (int, error) {
	var gen int
	err := s.db.QueryRow(ctx, `SELECT COALESCE(MAX(sync_generation), 0) FROM vex_statements`).Scan(&gen)
	return gen, err
}

// DeleteOldGenerations removes all rows whose generation is less than newGen.
// Returns the number of deleted rows.
func (s *VEXService) DeleteOldGenerations(ctx context.Context, newGen int) (int64, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM vex_statements WHERE sync_generation < $1`, newGen)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// GetLastSyncTime returns the timestamp of the last successful VEX sync, or nil.
func (s *VEXService) GetLastSyncTime(ctx context.Context) (*time.Time, error) {
	var lastSync *time.Time
	err := s.db.QueryRow(ctx, `
		SELECT last_sync_at FROM sync_status
		WHERE source_type = 'vex' AND source_name = 'vex' AND status = 'success'
		ORDER BY last_sync_at DESC LIMIT 1
	`).Scan(&lastSync)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	return lastSync, nil
}

// UpdateSyncStatus upserts the VEX sync status record.
func (s *VEXService) UpdateSyncStatus(ctx context.Context, status, errorMsg string, recordsProcessed int) {
	_, err := s.db.Exec(ctx, `
		INSERT INTO sync_status (source_type, source_name, status, last_sync_at, error_message, records_processed, updated_at)
		VALUES ('vex', 'vex', $1, NOW(), $2, $3, NOW())
		ON CONFLICT (source_type, source_name) DO UPDATE SET
			status            = EXCLUDED.status,
			last_sync_at      = EXCLUDED.last_sync_at,
			error_message     = EXCLUDED.error_message,
			records_processed = EXCLUDED.records_processed,
			updated_at        = NOW()
	`, status, errorMsg, recordsProcessed)
	if err != nil {
		log.Error().Err(err).Msg("Failed to update VEX sync status")
	}
}

// GetSyncStatus returns the current VEX sync status for the admin UI.
func (s *VEXService) GetSyncStatus(ctx context.Context) (*models.SyncStatus, error) {
	var ss models.SyncStatus
	var errMsg *string
	err := s.db.QueryRow(ctx, `
		SELECT id, source_type, source_name, status, last_sync_at,
		       error_message, records_processed
		FROM sync_status
		WHERE source_type = 'vex' AND source_name = 'vex'
		LIMIT 1
	`).Scan(&ss.ID, &ss.SyncType, &ss.SourceName, &ss.Status,
		&ss.StartedAt, &errMsg, &ss.ItemsProcessed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if errMsg != nil {
		ss.ErrorMessage = *errMsg
	}
	return &ss, nil
}

// GetStatementCount returns the total number of VEX statements in the database.
func (s *VEXService) GetStatementCount(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM vex_statements`).Scan(&count)
	return count, err
}

// EnrichFindings updates vex_status and vex_justification for all active
// findings on a server in a single SQL statement. distro is the Ubuntu codename
// (e.g. "focal", "jammy"). Returns the number of rows enriched.
func (s *VEXService) EnrichFindings(ctx context.Context, serverID int64, distro string) (int64, error) {
	if distro == "" {
		return 0, nil
	}
	tag, err := s.db.Exec(ctx, `
		UPDATE findings f
		SET
			vex_status        = v.status,
			vex_justification = v.justification,
			-- VEX will_not_fix overrides OVAL 'affected' (no fix known), but never overrides
			-- 'fix_available' — a known fix takes precedence over Canonical's won't-fix stance.
			fix_state         = CASE
				WHEN v.status = 'will_not_fix' AND f.fix_state = 'affected' THEN 'will_not_fix'
				ELSE f.fix_state
			END,
			updated_at        = NOW()
		FROM (
			SELECT DISTINCT ON (cve_id, package_name)
				cve_id, package_name, status, justification
			FROM vex_statements
			WHERE distro = $2
			  AND status != 'fixed'
			ORDER BY cve_id, package_name,
				CASE status
					WHEN 'not_affected'        THEN 0
					WHEN 'under_investigation' THEN 1
					WHEN 'will_not_fix'        THEN 2
					ELSE 3
				END
		) v
		WHERE f.server_id  = $1
		  AND f.resolved_at IS NULL
		  AND f.cve_id       = v.cve_id
		  AND f.package_name = v.package_name
	`, serverID, distro)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
