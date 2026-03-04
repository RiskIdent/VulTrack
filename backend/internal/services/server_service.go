package services

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/models"
)

// ServerService handles server-related operations
type ServerService struct {
	db *pgxpool.Pool
}

// NewServerService creates a new ServerService
func NewServerService(db *pgxpool.Pool) *ServerService {
	return &ServerService{db: db}
}

// GetAll returns all servers with finding counts
func (s *ServerService) GetAll(ctx context.Context) ([]models.Server, error) {
	query := `
		SELECT 
			s.id, s.name, s.os_family, s.os_release, 
			COALESCE(s.os_codename, ''), COALESCE(s.kernel, ''), 
			COALESCE(s.arch, ''), COALESCE(s.package_manager, ''),
			s.ipv4_addrs, s.last_scan_at, s.created_at, s.updated_at,
			COUNT(f.id) FILTER (WHERE f.resolved_at IS NULL) as findings_count,
			COUNT(f.id) FILTER (WHERE f.resolved_at IS NULL AND LOWER(f.severity) = 'critical') as critical_count,
			COUNT(f.id) FILTER (WHERE f.resolved_at IS NULL AND LOWER(f.severity) = 'high') as high_count
		FROM servers s
		LEFT JOIN findings f ON s.id = f.server_id
		GROUP BY s.id
		ORDER BY s.name
	`

	rows, err := s.db.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []models.Server
	for rows.Next() {
		var srv models.Server
		err := rows.Scan(
			&srv.ID, &srv.Name, &srv.OSFamily, &srv.OSRelease,
			&srv.OSCodename, &srv.Kernel, &srv.Arch, &srv.PackageManager,
			&srv.IPv4Addrs, &srv.LastScanAt, &srv.CreatedAt, &srv.UpdatedAt,
			&srv.FindingsCount, &srv.CriticalCount, &srv.HighCount,
		)
		if err != nil {
			return nil, err
		}
		servers = append(servers, srv)
	}

	return servers, nil
}

// GetByID returns a server by ID
func (s *ServerService) GetByID(ctx context.Context, id int64) (*models.Server, error) {
	query := `
		SELECT 
			s.id, s.name, s.os_family, s.os_release, 
			COALESCE(s.os_codename, ''), COALESCE(s.kernel, ''), 
			COALESCE(s.arch, ''), COALESCE(s.package_manager, ''),
			s.ipv4_addrs, s.last_scan_at, s.created_at, s.updated_at,
			COUNT(f.id) FILTER (WHERE f.resolved_at IS NULL) as findings_count,
			COUNT(f.id) FILTER (WHERE f.resolved_at IS NULL AND LOWER(f.severity) = 'critical') as critical_count,
			COUNT(f.id) FILTER (WHERE f.resolved_at IS NULL AND LOWER(f.severity) = 'high') as high_count
		FROM servers s
		LEFT JOIN findings f ON s.id = f.server_id
		WHERE s.id = $1
		GROUP BY s.id
	`

	var srv models.Server
	err := s.db.QueryRow(ctx, query, id).Scan(
		&srv.ID, &srv.Name, &srv.OSFamily, &srv.OSRelease,
		&srv.OSCodename, &srv.Kernel, &srv.Arch, &srv.PackageManager,
		&srv.IPv4Addrs, &srv.LastScanAt, &srv.CreatedAt, &srv.UpdatedAt,
		&srv.FindingsCount, &srv.CriticalCount, &srv.HighCount,
	)
	if err != nil {
		return nil, err
	}

	return &srv, nil
}

// GetByName returns a server by name
func (s *ServerService) GetByName(ctx context.Context, name string) (*models.Server, error) {
	query := `
		SELECT id, name, os_family, os_release, 
			COALESCE(os_codename, ''), COALESCE(kernel, ''), 
			COALESCE(arch, ''), COALESCE(package_manager, ''),
			ipv4_addrs, last_scan_at, created_at, updated_at
		FROM servers
		WHERE name = $1
	`

	var srv models.Server
	err := s.db.QueryRow(ctx, query, name).Scan(
		&srv.ID, &srv.Name, &srv.OSFamily, &srv.OSRelease,
		&srv.OSCodename, &srv.Kernel, &srv.Arch, &srv.PackageManager,
		&srv.IPv4Addrs, &srv.LastScanAt, &srv.CreatedAt, &srv.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &srv, nil
}

// Upsert creates or updates a server
func (s *ServerService) Upsert(ctx context.Context, srv *models.Server) (*models.Server, error) {
	query := `
		INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager, ipv4_addrs, last_scan_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
		ON CONFLICT (name) 
		DO UPDATE SET 
			os_family = EXCLUDED.os_family,
			os_release = EXCLUDED.os_release,
			os_codename = EXCLUDED.os_codename,
			kernel = EXCLUDED.kernel,
			arch = EXCLUDED.arch,
			package_manager = EXCLUDED.package_manager,
			ipv4_addrs = EXCLUDED.ipv4_addrs,
			last_scan_at = EXCLUDED.last_scan_at,
			updated_at = NOW()
		RETURNING id, name, os_family, os_release, 
			COALESCE(os_codename, ''), COALESCE(kernel, ''), 
			COALESCE(arch, ''), COALESCE(package_manager, ''),
			ipv4_addrs, last_scan_at, created_at, updated_at
	`

	var result models.Server
	err := s.db.QueryRow(ctx, query,
		srv.Name, srv.OSFamily, srv.OSRelease, srv.OSCodename, srv.Kernel, srv.Arch, srv.PackageManager, srv.IPv4Addrs, srv.LastScanAt,
	).Scan(
		&result.ID, &result.Name, &result.OSFamily, &result.OSRelease,
		&result.OSCodename, &result.Kernel, &result.Arch, &result.PackageManager,
		&result.IPv4Addrs, &result.LastScanAt, &result.CreatedAt, &result.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateLastScan updates the last scan timestamp
func (s *ServerService) UpdateLastScan(ctx context.Context, id int64, scannedAt time.Time) error {
	query := `UPDATE servers SET last_scan_at = $1, updated_at = NOW() WHERE id = $2`
	_, err := s.db.Exec(ctx, query, scannedAt, id)
	return err
}

// Delete deletes a server and all its associated data (findings, packages, etc.)
// Due to CASCADE constraints, deleting a server will automatically delete:
// - All findings for this server
// - All server packages for this server
// - All server group memberships for this server
// Registered agents will have their server_id set to NULL
func (s *ServerService) Delete(ctx context.Context, id int64) error {
	query := `DELETE FROM servers WHERE id = $1`
	result, err := s.db.Exec(ctx, query, id)
	if err != nil {
		return err
	}

	// Check if server was actually deleted
	if result.RowsAffected() == 0 {
		return fmt.Errorf("server not found")
	}

	return nil
}
