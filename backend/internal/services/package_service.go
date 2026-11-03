package services

import (
	"context"
	"fmt"
	"strings"
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

// InstalledPackage is one package installed on one server, as listed on the
// APT Packages page.
type InstalledPackage struct {
	ID              int64     `json:"id"`
	ServerID        int64     `json:"serverId"`
	ServerName      string    `json:"serverName"`
	OS              string    `json:"os"` // e.g. "ubuntu 24.04 (noble)"
	Name            string    `json:"name"`
	Version         string    `json:"version"`
	PreviousVersion string    `json:"previousVersion,omitempty"`
	Arch            string    `json:"arch"`
	SourcePackage   string    `json:"sourcePackage"`
	FirstSeenAt     time.Time `json:"firstSeenAt"`
	LastSeenAt      time.Time `json:"lastSeenAt"`
}

// InstalledPackageFilter narrows ListInstalled. Every text field is a
// case-insensitive substring match on its column; empty fields are ignored.
type InstalledPackageFilter struct {
	ExactName     string // the package name exactly, e.g. for one package's detail page
	Name          string
	Version       string
	Arch          string
	SourcePackage string
	Server        string
	OS            string
	SortBy        string // name, version, arch, sourcePackage, serverName, os, firstSeenAt, lastSeenAt
	SortOrder     string // asc (default) or desc
	Limit         int
	Offset        int
}

// installedPackageOS renders a server's OS the same way for display and filter.
const installedPackageOS = `TRIM(CONCAT_WS(' ', srv.os_family, srv.os_release,
	CASE WHEN COALESCE(srv.os_codename, '') <> '' THEN '(' || srv.os_codename || ')' END))`

// escapeLike makes s match literally inside a LIKE pattern.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// installedPackagesFrom builds the FROM/WHERE clause over the installed
// packages that match f's filters, and the arguments it binds.
func installedPackagesFrom(f InstalledPackageFilter) (string, []any) {
	where := []string{"sp.removed_at IS NULL"}
	var args []any
	if f.ExactName != "" {
		args = append(args, f.ExactName)
		where = append(where, fmt.Sprintf("sp.name = $%d", len(args)))
	}
	contains := func(expr, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		args = append(args, "%"+escapeLike(value)+"%")
		where = append(where, fmt.Sprintf("%s ILIKE $%d", expr, len(args)))
	}
	contains("sp.name", f.Name)
	contains("sp.version", f.Version)
	contains("COALESCE(sp.arch, '')", f.Arch)
	contains("COALESCE(sp.source_package, '')", f.SourcePackage)
	contains("srv.name", f.Server)
	contains(installedPackageOS, f.OS)

	return `
		FROM server_packages sp
		JOIN servers srv ON srv.id = sp.server_id
		WHERE ` + strings.Join(where, " AND "), args
}

// normalizePage applies the default and ceiling to a page request.
func normalizePage(limit, offset int) (int, int) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	return limit, max(offset, 0)
}

// ListInstalled returns the packages currently installed on any server, one
// row per server and package, filtered and sorted server-side, and the total
// number of matching rows.
func (s *PackageService) ListInstalled(ctx context.Context, f InstalledPackageFilter) ([]InstalledPackage, int, error) {
	from, args := installedPackagesFrom(f)

	var total int
	if err := s.db.QueryRow(ctx, "SELECT COUNT(*)"+from, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	columns := map[string]string{
		"name":          "sp.name",
		"version":       "sp.version",
		"arch":          "sp.arch",
		"sourcePackage": "sp.source_package",
		"serverName":    "srv.name",
		"os":            installedPackageOS,
		"firstSeenAt":   "sp.first_seen_at",
		"lastSeenAt":    "sp.last_seen_at",
	}
	col, ok := columns[f.SortBy]
	if !ok {
		col = "sp.name"
	}
	dir := "ASC"
	if f.SortOrder == "desc" {
		dir = "DESC"
	}
	f.Limit, f.Offset = normalizePage(f.Limit, f.Offset)
	args = append(args, f.Limit, f.Offset)

	rows, err := s.db.Query(ctx, fmt.Sprintf(`
		SELECT sp.id, sp.server_id, srv.name, %s,
		       sp.name, sp.version, COALESCE(sp.previous_version, ''),
		       COALESCE(sp.arch, ''), COALESCE(sp.source_package, ''),
		       sp.first_seen_at, sp.last_seen_at
		%s
		ORDER BY %s %s NULLS LAST, sp.name, srv.name, sp.id
		LIMIT $%d OFFSET $%d
	`, installedPackageOS, from, col, dir, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	packages := []InstalledPackage{}
	for rows.Next() {
		var p InstalledPackage
		if err := rows.Scan(&p.ID, &p.ServerID, &p.ServerName, &p.OS,
			&p.Name, &p.Version, &p.PreviousVersion, &p.Arch, &p.SourcePackage,
			&p.FirstSeenAt, &p.LastSeenAt); err != nil {
			return nil, 0, err
		}
		packages = append(packages, p)
	}
	return packages, total, rows.Err()
}

// PackageSummary is one package name across all servers, as listed on the APT
// Packages page. Counts cover only the installations that match the filter.
type PackageSummary struct {
	Name           string    `json:"name"`
	SourcePackages []string  `json:"sourcePackages"`
	Versions       []string  `json:"versions"`
	Archs          []string  `json:"archs"`
	ServerCount    int       `json:"serverCount"`
	LastSeenAt     time.Time `json:"lastSeenAt"`
}

// ListPackageSummaries returns each installed package once, with its distinct
// versions, architectures and source packages and the number of servers it is
// installed on. The filters work as in ListInstalled; SortBy takes name,
// sourcePackage, versionCount, serverCount or lastSeenAt.
func (s *PackageService) ListPackageSummaries(ctx context.Context, f InstalledPackageFilter) ([]PackageSummary, int, error) {
	from, args := installedPackagesFrom(f)

	var total int
	if err := s.db.QueryRow(ctx, "SELECT COUNT(DISTINCT sp.name)"+from, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	columns := map[string]string{
		"name":          "sp.name",
		"sourcePackage": "MIN(sp.source_package)",
		"versionCount":  "COUNT(DISTINCT sp.version)",
		"serverCount":   "COUNT(DISTINCT sp.server_id)",
		"lastSeenAt":    "MAX(sp.last_seen_at)",
	}
	col, ok := columns[f.SortBy]
	if !ok {
		col = "sp.name"
	}
	dir := "ASC"
	if f.SortOrder == "desc" {
		dir = "DESC"
	}
	f.Limit, f.Offset = normalizePage(f.Limit, f.Offset)
	args = append(args, f.Limit, f.Offset)

	rows, err := s.db.Query(ctx, fmt.Sprintf(`
		SELECT sp.name,
		       ARRAY_REMOVE(ARRAY_AGG(DISTINCT NULLIF(sp.source_package, '')), NULL),
		       ARRAY_AGG(DISTINCT sp.version),
		       ARRAY_REMOVE(ARRAY_AGG(DISTINCT NULLIF(sp.arch, '')), NULL),
		       COUNT(DISTINCT sp.server_id),
		       MAX(sp.last_seen_at)
		%s
		GROUP BY sp.name
		ORDER BY %s %s NULLS LAST, sp.name
		LIMIT $%d OFFSET $%d
	`, from, col, dir, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	summaries := []PackageSummary{}
	for rows.Next() {
		var p PackageSummary
		if err := rows.Scan(&p.Name, &p.SourcePackages, &p.Versions, &p.Archs, &p.ServerCount, &p.LastSeenAt); err != nil {
			return nil, 0, err
		}
		summaries = append(summaries, p)
	}
	return summaries, total, rows.Err()
}
