package services

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/models"
)

// PackageService handles server package management
type PackageService struct {
	db *pgxpool.Pool
}

// NewPackageService creates a new PackageService
func NewPackageService(db *pgxpool.Pool) *PackageService {
	return &PackageService{db: db}
}

// SyncPackages synchronizes the package list for a server
// - New packages are inserted
// - Existing packages are updated (version, last_seen_at)
// - Missing packages are soft-deleted (removed_at set)
// - Previously removed packages that reappear are restored
func (s *PackageService) SyncPackages(ctx context.Context, serverID int64, packages []models.PackageInfo) error {
	now := time.Now()

	// Start transaction
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Get current active packages for this server
	existingPackages := make(map[string]models.ServerPackage)
	rows, err := tx.Query(ctx, `
		SELECT id, name, version, arch, source_package, first_seen_at, last_seen_at
		FROM server_packages
		WHERE server_id = $1 AND removed_at IS NULL
	`, serverID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var pkg models.ServerPackage
		err := rows.Scan(&pkg.ID, &pkg.Name, &pkg.Version, &pkg.Arch, &pkg.SourcePackage, &pkg.FirstSeenAt, &pkg.LastSeenAt)
		if err != nil {
			rows.Close()
			return err
		}
		key := pkg.Name + "|" + pkg.Arch
		existingPackages[key] = pkg
	}
	rows.Close()

	// Track which packages are in the new report
	reportedPackages := make(map[string]bool)

	// Process each package from the report
	for _, pkg := range packages {
		key := pkg.Name + "|" + pkg.Arch
		reportedPackages[key] = true

		if existing, found := existingPackages[key]; found {
			// Package exists - update it
			if existing.Version != pkg.Version {
				// Version changed - update with previous version tracking
				_, err = tx.Exec(ctx, `
				UPDATE server_packages
				SET version = $2, previous_version = $3, source_package = $4, 
				    last_seen_at = $5, updated_at = $5
				WHERE id = $1
			`, existing.ID, pkg.Version, existing.Version, pkg.Source, now)
			} else {
				// Just update last_seen_at
				_, err = tx.Exec(ctx, `
					UPDATE server_packages
					SET last_seen_at = $2, updated_at = $2
					WHERE id = $1
				`, existing.ID, now)
			}
			if err != nil {
				return err
			}
		} else {
			// Check if package was previously removed
			var removedPkgID int64
			err = tx.QueryRow(ctx, `
				SELECT id FROM server_packages
				WHERE server_id = $1 AND name = $2 AND arch = $3 AND removed_at IS NOT NULL
			`, serverID, pkg.Name, pkg.Arch).Scan(&removedPkgID)

			if err == nil {
				// Package was removed, restore it
				_, err = tx.Exec(ctx, `
					UPDATE server_packages
					SET version = $2, source_package = $3, last_seen_at = $4, 
					    removed_at = NULL, updated_at = $4
					WHERE id = $1
				`, removedPkgID, pkg.Version, pkg.Source, now)
			} else {
				// New package - insert it
				_, err = tx.Exec(ctx, `
					INSERT INTO server_packages (server_id, name, version, arch, source_package, first_seen_at, last_seen_at)
					VALUES ($1, $2, $3, $4, $5, $6, $6)
				`, serverID, pkg.Name, pkg.Version, pkg.Arch, pkg.Source, now)
			}
			if err != nil {
				return err
			}
		}
	}

	// Soft-delete packages that are no longer in the report
	for key, existing := range existingPackages {
		if !reportedPackages[key] {
			_, err = tx.Exec(ctx, `
				UPDATE server_packages
				SET removed_at = $2, updated_at = $2
				WHERE id = $1
			`, existing.ID, now)
			if err != nil {
				return err
			}
		}
	}

	return tx.Commit(ctx)
}

// GetByServerID returns all packages for a server
func (s *PackageService) GetByServerID(ctx context.Context, serverID int64, includeRemoved bool) ([]models.ServerPackage, error) {
	query := `
		SELECT id, server_id, name, version, 
		       COALESCE(previous_version, ''), COALESCE(arch, ''), COALESCE(source_package, ''),
		       first_seen_at, last_seen_at, removed_at, created_at, updated_at
		FROM server_packages
		WHERE server_id = $1
	`
	if !includeRemoved {
		query += " AND removed_at IS NULL"
	}
	query += " ORDER BY name ASC"

	rows, err := s.db.Query(ctx, query, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var packages []models.ServerPackage
	for rows.Next() {
		var pkg models.ServerPackage
		err := rows.Scan(
			&pkg.ID,
			&pkg.ServerID,
			&pkg.Name,
			&pkg.Version,
			&pkg.PreviousVersion,
			&pkg.Arch,
			&pkg.SourcePackage,
			&pkg.FirstSeenAt,
			&pkg.LastSeenAt,
			&pkg.RemovedAt,
			&pkg.CreatedAt,
			&pkg.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

// GetActivePackageCount returns the count of active (non-removed) packages for a server
func (s *PackageService) GetActivePackageCount(ctx context.Context, serverID int64) (int, error) {
	var count int
	err := s.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM server_packages
		WHERE server_id = $1 AND removed_at IS NULL
	`, serverID).Scan(&count)
	return count, err
}

// GetRecentlyRemovedPackages returns packages removed in the last N days
func (s *PackageService) GetRecentlyRemovedPackages(ctx context.Context, serverID int64, days int) ([]models.ServerPackage, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, server_id, name, version, previous_version, arch, source_package,
		       first_seen_at, last_seen_at, removed_at, created_at, updated_at
		FROM server_packages
		WHERE server_id = $1 
		  AND removed_at IS NOT NULL 
		  AND removed_at > NOW() - ($2 || ' days')::INTERVAL
		ORDER BY removed_at DESC
	`, serverID, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var packages []models.ServerPackage
	for rows.Next() {
		var pkg models.ServerPackage
		err := rows.Scan(
			&pkg.ID,
			&pkg.ServerID,
			&pkg.Name,
			&pkg.Version,
			&pkg.PreviousVersion,
			&pkg.Arch,
			&pkg.SourcePackage,
			&pkg.FirstSeenAt,
			&pkg.LastSeenAt,
			&pkg.RemovedAt,
			&pkg.CreatedAt,
			&pkg.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

// GetRecentlyUpdatedPackages returns packages that had version changes in the last N days
func (s *PackageService) GetRecentlyUpdatedPackages(ctx context.Context, serverID int64, days int) ([]models.ServerPackage, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, server_id, name, version, previous_version, arch, source_package,
		       first_seen_at, last_seen_at, removed_at, created_at, updated_at
		FROM server_packages
		WHERE server_id = $1 
		  AND previous_version IS NOT NULL 
		  AND updated_at > NOW() - ($2 || ' days')::INTERVAL
		  AND removed_at IS NULL
		ORDER BY updated_at DESC
	`, serverID, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var packages []models.ServerPackage
	for rows.Next() {
		var pkg models.ServerPackage
		err := rows.Scan(
			&pkg.ID,
			&pkg.ServerID,
			&pkg.Name,
			&pkg.Version,
			&pkg.PreviousVersion,
			&pkg.Arch,
			&pkg.SourcePackage,
			&pkg.FirstSeenAt,
			&pkg.LastSeenAt,
			&pkg.RemovedAt,
			&pkg.CreatedAt,
			&pkg.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

// SearchPackages searches for packages by name across all servers
func (s *PackageService) SearchPackages(ctx context.Context, namePattern string, limit int) ([]models.ServerPackage, error) {
	rows, err := s.db.Query(ctx, `
		SELECT sp.id, sp.server_id, sp.name, sp.version, sp.arch, sp.source_package,
		       sp.first_seen_at, sp.last_seen_at, sp.removed_at
		FROM server_packages sp
		WHERE sp.name ILIKE $1 AND sp.removed_at IS NULL
		ORDER BY sp.name, sp.server_id
		LIMIT $2
	`, "%"+namePattern+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var packages []models.ServerPackage
	for rows.Next() {
		var pkg models.ServerPackage
		err := rows.Scan(
			&pkg.ID,
			&pkg.ServerID,
			&pkg.Name,
			&pkg.Version,
			&pkg.Arch,
			&pkg.SourcePackage,
			&pkg.FirstSeenAt,
			&pkg.LastSeenAt,
			&pkg.RemovedAt,
		)
		if err != nil {
			return nil, err
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}
