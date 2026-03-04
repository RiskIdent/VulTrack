package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/auth"
	"github.com/vultrack/vultrack/internal/models"
)

// AgentService handles registered agent management
type AgentService struct {
	db *pgxpool.Pool
}

// NewAgentService creates a new AgentService
func NewAgentService(db *pgxpool.Pool) *AgentService {
	return &AgentService{db: db}
}

// RegisterAgent registers a new agent and returns the agent token
// Returns the full token (to return to the agent) and the registered agent record
func (s *AgentService) RegisterAgent(ctx context.Context, hostname string, enrollmentKeyID int64, autoApprove bool) (*models.RegisteredAgent, string, error) {
	// Generate token
	fullToken, prefix, err := auth.GenerateAgentToken()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate token: %w", err)
	}

	// Hash the token for storage
	tokenHash := auth.HashKey(fullToken)

	// Determine initial status
	status := models.AgentStatusPending
	if autoApprove {
		status = models.AgentStatusActive
	}

	var agent models.RegisteredAgent
	err = s.db.QueryRow(ctx, `
		INSERT INTO registered_agents (hostname, token_hash, token_prefix, enrolled_via, status, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		RETURNING id, hostname, token_prefix, enrolled_via, status, last_seen_at, created_at
	`, hostname, tokenHash, prefix, enrollmentKeyID, status).Scan(
		&agent.ID,
		&agent.Hostname,
		&agent.TokenPrefix,
		&agent.EnrolledVia,
		&agent.Status,
		&agent.LastSeenAt,
		&agent.CreatedAt,
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to register agent: %w", err)
	}

	return &agent, fullToken, nil
}

// ValidateToken validates an agent token and returns the agent if valid
func (s *AgentService) ValidateToken(ctx context.Context, token string) (*models.RegisteredAgent, error) {
	// Validate format
	if !auth.ValidateAgentToken(token) {
		return nil, errors.New("invalid token format")
	}

	// Hash the provided token
	tokenHash := auth.HashKey(token)

	var agent models.RegisteredAgent
	var lastIP, agentVersion, enrollmentKeyName *string
	err := s.db.QueryRow(ctx, `
		SELECT ra.id, ra.server_id, ra.hostname, ra.token_prefix, ra.enrolled_via, ra.status, 
		       ra.last_seen_at, ra.last_ip, ra.agent_version, ra.created_at, ek.name as enrollment_key_name
		FROM registered_agents ra
		LEFT JOIN enrollment_keys ek ON ra.enrolled_via = ek.id
		WHERE ra.token_hash = $1
	`, tokenHash).Scan(
		&agent.ID,
		&agent.ServerID,
		&agent.Hostname,
		&agent.TokenPrefix,
		&agent.EnrolledVia,
		&agent.Status,
		&agent.LastSeenAt,
		&lastIP,
		&agentVersion,
		&agent.CreatedAt,
		&enrollmentKeyName,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("invalid agent token")
		}
		return nil, err
	}

	if lastIP != nil {
		agent.LastIP = *lastIP
	}
	if agentVersion != nil {
		agent.AgentVersion = *agentVersion
	}
	if enrollmentKeyName != nil {
		agent.EnrollmentKeyName = *enrollmentKeyName
	}

	// Check if agent is active
	if agent.Status != models.AgentStatusActive {
		return nil, fmt.Errorf("agent status is %s, not active", agent.Status)
	}

	return &agent, nil
}

// UpdateLastSeen updates the last seen timestamp, IP and agent version for an agent
func (s *AgentService) UpdateLastSeen(ctx context.Context, agentID int64, ip string, agentVersion string) error {
	_, err := s.db.Exec(ctx, `
		UPDATE registered_agents
		SET last_seen_at = NOW(), last_ip = $2, agent_version = $3
		WHERE id = $1
	`, agentID, ip, agentVersion)
	return err
}

// LinkToServer links an agent to a server record
func (s *AgentService) LinkToServer(ctx context.Context, agentID int64, serverID int64) error {
	_, err := s.db.Exec(ctx, `
		UPDATE registered_agents
		SET server_id = $2
		WHERE id = $1
	`, agentID, serverID)
	return err
}

// GetAll returns all registered agents
func (s *AgentService) GetAll(ctx context.Context, statusFilter string) ([]models.RegisteredAgent, error) {
	query := `
		SELECT ra.id, ra.server_id, ra.hostname, ra.token_prefix, ra.enrolled_via, ra.status, 
		       ra.last_seen_at, ra.last_ip, ra.agent_version, ra.created_at, ek.name as enrollment_key_name
		FROM registered_agents ra
		LEFT JOIN enrollment_keys ek ON ra.enrolled_via = ek.id
	`
	var args []interface{}
	if statusFilter != "" {
		query += " WHERE ra.status = $1"
		args = append(args, statusFilter)
	}
	query += " ORDER BY ra.created_at DESC"

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []models.RegisteredAgent
	for rows.Next() {
		var agent models.RegisteredAgent
		var lastIP, agentVersion, enrollmentKeyName *string
		err := rows.Scan(
			&agent.ID,
			&agent.ServerID,
			&agent.Hostname,
			&agent.TokenPrefix,
			&agent.EnrolledVia,
			&agent.Status,
			&agent.LastSeenAt,
			&lastIP,
			&agentVersion,
			&agent.CreatedAt,
			&enrollmentKeyName,
		)
		if err != nil {
			return nil, err
		}
		if lastIP != nil {
			agent.LastIP = *lastIP
		}
		if agentVersion != nil {
			agent.AgentVersion = *agentVersion
		}
		if enrollmentKeyName != nil {
			agent.EnrollmentKeyName = *enrollmentKeyName
		}
		agents = append(agents, agent)
	}

	return agents, nil
}

// GetByID returns an agent by ID
func (s *AgentService) GetByID(ctx context.Context, id int64) (*models.RegisteredAgent, error) {
	var agent models.RegisteredAgent
	var lastIP, agentVersion, enrollmentKeyName *string
	err := s.db.QueryRow(ctx, `
		SELECT ra.id, ra.server_id, ra.hostname, ra.token_prefix, ra.enrolled_via, ra.status, 
		       ra.last_seen_at, ra.last_ip, ra.agent_version, ra.created_at, ek.name as enrollment_key_name
		FROM registered_agents ra
		LEFT JOIN enrollment_keys ek ON ra.enrolled_via = ek.id
		WHERE ra.id = $1
	`, id).Scan(
		&agent.ID,
		&agent.ServerID,
		&agent.Hostname,
		&agent.TokenPrefix,
		&agent.EnrolledVia,
		&agent.Status,
		&agent.LastSeenAt,
		&lastIP,
		&agentVersion,
		&agent.CreatedAt,
		&enrollmentKeyName,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if lastIP != nil {
		agent.LastIP = *lastIP
	}
	if agentVersion != nil {
		agent.AgentVersion = *agentVersion
	}
	if enrollmentKeyName != nil {
		agent.EnrollmentKeyName = *enrollmentKeyName
	}

	return &agent, nil
}

// Approve approves a pending agent
func (s *AgentService) Approve(ctx context.Context, id int64) error {
	result, err := s.db.Exec(ctx, `
		UPDATE registered_agents
		SET status = $2
		WHERE id = $1 AND status = $3
	`, id, models.AgentStatusActive, models.AgentStatusPending)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return errors.New("agent not found or not in pending status")
	}

	return nil
}

// Revoke revokes an agent's access
func (s *AgentService) Revoke(ctx context.Context, id int64) error {
	result, err := s.db.Exec(ctx, `
		UPDATE registered_agents
		SET status = $2
		WHERE id = $1
	`, id, models.AgentStatusRevoked)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return errors.New("agent not found")
	}

	return nil
}

// Delete deletes an agent
func (s *AgentService) Delete(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM registered_agents WHERE id = $1`, id)
	return err
}

// GetByHostname returns an agent by hostname (for checking duplicates)
func (s *AgentService) GetByHostname(ctx context.Context, hostname string) (*models.RegisteredAgent, error) {
	var agent models.RegisteredAgent
	var lastIP, agentVersion *string
	err := s.db.QueryRow(ctx, `
		SELECT id, server_id, hostname, token_prefix, enrolled_via, status, 
		       last_seen_at, last_ip, agent_version, created_at
		FROM registered_agents
		WHERE hostname = $1 AND status != $2
		ORDER BY created_at DESC
		LIMIT 1
	`, hostname, models.AgentStatusRevoked).Scan(
		&agent.ID,
		&agent.ServerID,
		&agent.Hostname,
		&agent.TokenPrefix,
		&agent.EnrolledVia,
		&agent.Status,
		&agent.LastSeenAt,
		&lastIP,
		&agentVersion,
		&agent.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if lastIP != nil {
		agent.LastIP = *lastIP
	}
	if agentVersion != nil {
		agent.AgentVersion = *agentVersion
	}

	return &agent, nil
}

// CountByStatus returns the count of agents by status
func (s *AgentService) CountByStatus(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.Query(ctx, `
		SELECT status, COUNT(*) 
		FROM registered_agents 
		GROUP BY status
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		counts[status] = count
	}

	return counts, nil
}

// GetAgentStats returns statistics about agents
func (s *AgentService) GetAgentStats(ctx context.Context) (map[string]interface{}, error) {
	counts, err := s.CountByStatus(ctx)
	if err != nil {
		return nil, err
	}

	// Count recently active (last 24 hours)
	var recentlyActive int
	err = s.db.QueryRow(ctx, `
		SELECT COUNT(*) 
		FROM registered_agents 
		WHERE status = $1 AND last_seen_at > NOW() - INTERVAL '24 hours'
	`, models.AgentStatusActive).Scan(&recentlyActive)
	if err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"total":          counts[models.AgentStatusActive] + counts[models.AgentStatusPending] + counts[models.AgentStatusRevoked],
		"active":         counts[models.AgentStatusActive],
		"pending":        counts[models.AgentStatusPending],
		"revoked":        counts[models.AgentStatusRevoked],
		"recentlyActive": recentlyActive,
	}

	return stats, nil
}
