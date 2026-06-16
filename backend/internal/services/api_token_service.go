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

// APITokenService handles API token management for the MCP interface.
type APITokenService struct {
	db *pgxpool.Pool
}

// NewAPITokenService creates a new APITokenService.
func NewAPITokenService(db *pgxpool.Pool) *APITokenService {
	return &APITokenService{db: db}
}

// Create creates a new API token.
// Returns the full token (to show once to the user) and the stored token record.
func (s *APITokenService) Create(ctx context.Context, description string, isReadOnly bool, createdBy *int64, expiresAt *time.Time) (*models.APIToken, string, error) {
	fullToken, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate token: %w", err)
	}

	tokenHash := auth.HashKey(fullToken)

	var token models.APIToken
	err = s.db.QueryRow(ctx, `
		INSERT INTO api_tokens (description, token_hash, token_prefix, is_read_only, is_active, created_by, expires_at)
		VALUES ($1, $2, $3, $4, true, $5, $6)
		RETURNING id, description, token_prefix, is_read_only, is_active, created_by, created_at, last_used_at, expires_at
	`, description, tokenHash, prefix, isReadOnly, createdBy, expiresAt).Scan(
		&token.ID,
		&token.Description,
		&token.TokenPrefix,
		&token.IsReadOnly,
		&token.IsActive,
		&token.CreatedBy,
		&token.CreatedAt,
		&token.LastUsedAt,
		&token.ExpiresAt,
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create API token: %w", err)
	}

	return &token, fullToken, nil
}

// GetAll returns all API tokens (without hashes).
func (s *APITokenService) GetAll(ctx context.Context) ([]models.APIToken, error) {
	rows, err := s.db.Query(ctx, `
		SELECT t.id, t.description, t.token_prefix, t.is_read_only, t.is_active,
		       t.created_by, t.created_at, t.last_used_at, t.expires_at,
		       COALESCE(NULLIF(u.name, ''), u.email, '') AS created_by_name
		FROM api_tokens t
		LEFT JOIN users u ON u.id = t.created_by
		ORDER BY t.created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []models.APIToken
	for rows.Next() {
		var t models.APIToken
		if err := rows.Scan(
			&t.ID,
			&t.Description,
			&t.TokenPrefix,
			&t.IsReadOnly,
			&t.IsActive,
			&t.CreatedBy,
			&t.CreatedAt,
			&t.LastUsedAt,
			&t.ExpiresAt,
			&t.CreatedByName,
		); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}

	return tokens, rows.Err()
}

// Delete deletes an API token.
func (s *APITokenService) Delete(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM api_tokens WHERE id = $1`, id)
	return err
}

// Authenticate validates a token string and returns the token record if valid.
// It also updates last_used_at as a side effect. Returns an error if the token
// has an invalid format, is unknown, inactive, or expired.
func (s *APITokenService) Authenticate(ctx context.Context, token string) (*models.APIToken, error) {
	if !auth.ValidateAPIToken(token) {
		return nil, errors.New("invalid token format")
	}

	tokenHash := auth.HashKey(token)

	var t models.APIToken
	err := s.db.QueryRow(ctx, `
		SELECT id, description, token_prefix, is_read_only, is_active, created_by, created_at, last_used_at, expires_at
		FROM api_tokens
		WHERE token_hash = $1
	`, tokenHash).Scan(
		&t.ID,
		&t.Description,
		&t.TokenPrefix,
		&t.IsReadOnly,
		&t.IsActive,
		&t.CreatedBy,
		&t.CreatedAt,
		&t.LastUsedAt,
		&t.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("invalid token")
		}
		return nil, err
	}

	if !t.IsActive {
		return nil, errors.New("token is not active")
	}
	if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
		return nil, errors.New("token has expired")
	}

	// Best-effort update of last_used_at; failures here must not block auth.
	_, _ = s.db.Exec(ctx, `UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1`, t.ID)

	return &t, nil
}
