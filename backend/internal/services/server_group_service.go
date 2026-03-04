package services

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/models"
)

// ServerGroupService handles server group operations
type ServerGroupService struct {
	db *pgxpool.Pool
}

// NewServerGroupService creates a new ServerGroupService
func NewServerGroupService(db *pgxpool.Pool) *ServerGroupService {
	return &ServerGroupService{db: db}
}

// GetAll returns all server groups with member counts
func (s *ServerGroupService) GetAll(ctx context.Context) ([]models.ServerGroup, error) {
	query := `
		SELECT 
			g.id, g.name, COALESCE(g.description, ''), g.color, 
			COUNT(m.server_id) as server_count,
			g.created_at, g.updated_at
		FROM server_groups g
		LEFT JOIN server_group_members m ON g.id = m.group_id
		GROUP BY g.id
		ORDER BY g.name
	`

	rows, err := s.db.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []models.ServerGroup
	for rows.Next() {
		var g models.ServerGroup
		err := rows.Scan(
			&g.ID, &g.Name, &g.Description, &g.Color,
			&g.ServerCount, &g.CreatedAt, &g.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}

	return groups, nil
}

// GetByID returns a server group by ID
func (s *ServerGroupService) GetByID(ctx context.Context, id int64) (*models.ServerGroup, error) {
	query := `
		SELECT 
			g.id, g.name, COALESCE(g.description, ''), g.color,
			COUNT(m.server_id) as server_count,
			g.created_at, g.updated_at
		FROM server_groups g
		LEFT JOIN server_group_members m ON g.id = m.group_id
		WHERE g.id = $1
		GROUP BY g.id
	`

	var g models.ServerGroup
	err := s.db.QueryRow(ctx, query, id).Scan(
		&g.ID, &g.Name, &g.Description, &g.Color,
		&g.ServerCount, &g.CreatedAt, &g.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &g, nil
}

// Create creates a new server group
func (s *ServerGroupService) Create(ctx context.Context, g *models.ServerGroup) (*models.ServerGroup, error) {
	query := `
		INSERT INTO server_groups (name, description, color)
		VALUES ($1, $2, $3)
		RETURNING id, name, COALESCE(description, ''), color, created_at, updated_at
	`

	var result models.ServerGroup
	err := s.db.QueryRow(ctx, query, g.Name, g.Description, g.Color).Scan(
		&result.ID, &result.Name, &result.Description, &result.Color,
		&result.CreatedAt, &result.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// Update updates a server group
func (s *ServerGroupService) Update(ctx context.Context, g *models.ServerGroup) (*models.ServerGroup, error) {
	query := `
		UPDATE server_groups
		SET name = $2, description = $3, color = $4, updated_at = NOW()
		WHERE id = $1
		RETURNING id, name, COALESCE(description, ''), color, created_at, updated_at
	`

	var result models.ServerGroup
	err := s.db.QueryRow(ctx, query, g.ID, g.Name, g.Description, g.Color).Scan(
		&result.ID, &result.Name, &result.Description, &result.Color,
		&result.CreatedAt, &result.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// Delete removes a server group
func (s *ServerGroupService) Delete(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM server_groups WHERE id = $1`, id)
	return err
}

// GetMembers returns all servers in a group
func (s *ServerGroupService) GetMembers(ctx context.Context, groupID int64) ([]models.Server, error) {
	query := `
		SELECT s.id, s.name, s.os_family, s.os_release, s.ipv4_addrs,
			s.last_scan_at, s.created_at, s.updated_at
		FROM servers s
		JOIN server_group_members m ON s.id = m.server_id
		WHERE m.group_id = $1
		ORDER BY s.name
	`

	rows, err := s.db.Query(ctx, query, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []models.Server
	for rows.Next() {
		var srv models.Server
		err := rows.Scan(
			&srv.ID, &srv.Name, &srv.OSFamily, &srv.OSRelease, &srv.IPv4Addrs,
			&srv.LastScanAt, &srv.CreatedAt, &srv.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		servers = append(servers, srv)
	}

	return servers, nil
}

// GetServerGroups returns all groups a server belongs to
func (s *ServerGroupService) GetServerGroups(ctx context.Context, serverID int64) ([]models.ServerGroup, error) {
	query := `
		SELECT g.id, g.name, COALESCE(g.description, ''), g.color, g.created_at, g.updated_at
		FROM server_groups g
		JOIN server_group_members m ON g.id = m.group_id
		WHERE m.server_id = $1
		ORDER BY g.name
	`

	rows, err := s.db.Query(ctx, query, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []models.ServerGroup
	for rows.Next() {
		var g models.ServerGroup
		err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.Color, &g.CreatedAt, &g.UpdatedAt)
		if err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}

	return groups, nil
}

// AddMember adds a server to a group
func (s *ServerGroupService) AddMember(ctx context.Context, groupID, serverID int64) error {
	query := `
		INSERT INTO server_group_members (group_id, server_id)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING
	`
	_, err := s.db.Exec(ctx, query, groupID, serverID)
	return err
}

// RemoveMember removes a server from a group
func (s *ServerGroupService) RemoveMember(ctx context.Context, groupID, serverID int64) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM server_group_members WHERE group_id = $1 AND server_id = $2`,
		groupID, serverID,
	)
	return err
}

// SetServerGroups replaces all group memberships for a server
func (s *ServerGroupService) SetServerGroups(ctx context.Context, serverID int64, groupIDs []int64) error {
	// Start transaction
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Remove all existing memberships
	_, err = tx.Exec(ctx, `DELETE FROM server_group_members WHERE server_id = $1`, serverID)
	if err != nil {
		return err
	}

	// Add new memberships
	for _, groupID := range groupIDs {
		_, err = tx.Exec(ctx,
			`INSERT INTO server_group_members (server_id, group_id) VALUES ($1, $2)`,
			serverID, groupID,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}
