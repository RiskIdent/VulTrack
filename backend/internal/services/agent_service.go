package services

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	var lastIP, agentVersion, enrollmentKeyName, authFailureIP *string
	err := s.db.QueryRow(ctx, `
		SELECT ra.id, ra.server_id, ra.hostname, ra.token_prefix, ra.enrolled_via, ra.status,
		       ra.last_seen_at, ra.last_ip, ra.agent_version, ra.created_at,
		       ra.last_auth_failure_at, ra.auth_failure_ip, ek.name as enrollment_key_name
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
		&agent.LastAuthFailureAt,
		&authFailureIP,
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
	if authFailureIP != nil {
		agent.AuthFailureIP = *authFailureIP
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
		       ra.last_seen_at, ra.last_ip, ra.agent_version, ra.created_at,
		       ra.last_auth_failure_at, ra.auth_failure_ip, ek.name as enrollment_key_name
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
		var lastIP, agentVersion, authFailureIP, enrollmentKeyName *string
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
			&agent.LastAuthFailureAt,
			&authFailureIP,
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
		if authFailureIP != nil {
			agent.AuthFailureIP = *authFailureIP
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
	var lastIP, agentVersion, authFailureIP, enrollmentKeyName *string
	err := s.db.QueryRow(ctx, `
		SELECT ra.id, ra.server_id, ra.hostname, ra.token_prefix, ra.enrolled_via, ra.status,
		       ra.last_seen_at, ra.last_ip, ra.agent_version, ra.created_at,
		       ra.last_auth_failure_at, ra.auth_failure_ip, ek.name as enrollment_key_name
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
		&agent.LastAuthFailureAt,
		&authFailureIP,
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
	if authFailureIP != nil {
		agent.AuthFailureIP = *authFailureIP
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

// ============================================================================
// V2 REFRESH TOKEN METHODS
// ============================================================================

// CreateRefreshToken creates and persists a new refresh token for the given agent.
// Returns the stored record and the full (unhashed) token to return to the caller once.
func (s *AgentService) CreateRefreshToken(ctx context.Context, agentID int64, ttlDays int) (*models.AgentRefreshToken, string, error) {
	fullToken, prefix, err := auth.GenerateRefreshToken()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	tokenHash := auth.HashKey(fullToken)
	expiresAt := time.Now().Add(time.Duration(ttlDays) * 24 * time.Hour)

	var rt models.AgentRefreshToken
	err = s.db.QueryRow(ctx, `
		INSERT INTO agent_refresh_tokens (agent_id, token_hash, token_prefix, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, agent_id, token_prefix, expires_at, created_at
	`, agentID, tokenHash, prefix, expiresAt).Scan(
		&rt.ID, &rt.AgentID, &rt.TokenPrefix, &rt.ExpiresAt, &rt.CreatedAt,
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to persist refresh token: %w", err)
	}
	return &rt, fullToken, nil
}

// ValidateAndRotateRefreshToken validates the supplied token, revokes it, issues a
// replacement, and returns the agent together with the new token string.
// This implements refresh-token rotation: each token can only be used once.
func (s *AgentService) ValidateAndRotateRefreshToken(ctx context.Context, token string, ttlDays int) (*models.RegisteredAgent, string, error) {
	if !auth.ValidateRefreshToken(token) {
		return nil, "", errors.New("invalid refresh token format")
	}
	tokenHash := auth.HashKey(token)

	// Load the refresh token record + owning agent in one query
	var rt models.AgentRefreshToken
	var revokedAt *time.Time
	var agent models.RegisteredAgent
	err := s.db.QueryRow(ctx, `
		SELECT rt.id, rt.agent_id, rt.expires_at, rt.revoked_at,
		       ra.id, ra.server_id, ra.hostname, ra.status
		FROM agent_refresh_tokens rt
		JOIN registered_agents ra ON rt.agent_id = ra.id
		WHERE rt.token_hash = $1
	`, tokenHash).Scan(
		&rt.ID, &rt.AgentID, &rt.ExpiresAt, &revokedAt,
		&agent.ID, &agent.ServerID, &agent.Hostname, &agent.Status,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", errors.New("invalid refresh token")
		}
		return nil, "", err
	}

	if revokedAt != nil {
		return nil, "", errors.New("refresh token has been revoked")
	}
	if time.Now().After(rt.ExpiresAt) {
		return nil, "", errors.New("refresh token has expired")
	}
	if agent.Status != models.AgentStatusActive {
		return nil, "", fmt.Errorf("agent status is %s, not active", agent.Status)
	}

	// Atomic rotation: revoke old token, insert new one
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		UPDATE agent_refresh_tokens
		SET revoked_at = NOW(), last_used_at = NOW()
		WHERE id = $1
	`, rt.ID)
	if err != nil {
		return nil, "", err
	}

	newFull, newPrefix, err := auth.GenerateRefreshToken()
	if err != nil {
		return nil, "", err
	}
	newHash := auth.HashKey(newFull)
	newExpires := time.Now().Add(time.Duration(ttlDays) * 24 * time.Hour)

	_, err = tx.Exec(ctx, `
		INSERT INTO agent_refresh_tokens (agent_id, token_hash, token_prefix, expires_at)
		VALUES ($1, $2, $3, $4)
	`, rt.AgentID, newHash, newPrefix, newExpires)
	if err != nil {
		return nil, "", err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}

	return &agent, newFull, nil
}

// RecordAuthFailure records a JWT authentication failure for an agent identified by ID.
// Only updates active agents — revoked agents are ignored so the warning
// does not get lost on a stale record after re-enrollment.
func (s *AgentService) RecordAuthFailure(ctx context.Context, agentID int64, ip string) error {
	_, err := s.db.Exec(ctx, `
		UPDATE registered_agents
		SET last_auth_failure_at = NOW(), auth_failure_ip = $2
		WHERE id = $1 AND status = 'active'
	`, agentID, ip)
	return err
}

// ClearAuthFailure clears the auth failure fields after a successful authentication.
func (s *AgentService) ClearAuthFailure(ctx context.Context, agentID int64) error {
	_, err := s.db.Exec(ctx, `
		UPDATE registered_agents
		SET last_auth_failure_at = NULL, auth_failure_ip = NULL
		WHERE id = $1
	`, agentID)
	return err
}

// RevokeAllRefreshTokens marks all active refresh tokens for an agent as revoked.
// Called when an agent is revoked or forcefully re-enrolled.
func (s *AgentService) RevokeAllRefreshTokens(ctx context.Context, agentID int64) error {
	_, err := s.db.Exec(ctx, `
		UPDATE agent_refresh_tokens
		SET revoked_at = NOW()
		WHERE agent_id = $1 AND revoked_at IS NULL
	`, agentID)
	return err
}
