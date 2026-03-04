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

// EnrollmentService handles enrollment key management
type EnrollmentService struct {
	db *pgxpool.Pool
}

// NewEnrollmentService creates a new EnrollmentService
func NewEnrollmentService(db *pgxpool.Pool) *EnrollmentService {
	return &EnrollmentService{db: db}
}

// CreateEnrollmentKey creates a new enrollment key
// Returns the full key (to show once to the user) and the stored enrollment key record
func (s *EnrollmentService) CreateEnrollmentKey(ctx context.Context, name string, autoApprove bool, expiresAt *time.Time) (*models.EnrollmentKey, string, error) {
	// Generate key
	fullKey, prefix, err := auth.GenerateEnrollmentKey()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate key: %w", err)
	}

	// Hash the key for storage
	keyHash := auth.HashKey(fullKey)

	var enrollmentKey models.EnrollmentKey
	err = s.db.QueryRow(ctx, `
		INSERT INTO enrollment_keys (name, key_hash, key_prefix, is_active, auto_approve, expires_at)
		VALUES ($1, $2, $3, true, $4, $5)
		RETURNING id, name, key_prefix, is_active, auto_approve, usage_count, created_at, expires_at
	`, name, keyHash, prefix, autoApprove, expiresAt).Scan(
		&enrollmentKey.ID,
		&enrollmentKey.Name,
		&enrollmentKey.KeyPrefix,
		&enrollmentKey.IsActive,
		&enrollmentKey.AutoApprove,
		&enrollmentKey.UsageCount,
		&enrollmentKey.CreatedAt,
		&enrollmentKey.ExpiresAt,
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create enrollment key: %w", err)
	}

	return &enrollmentKey, fullKey, nil
}

// GetAll returns all enrollment keys
func (s *EnrollmentService) GetAll(ctx context.Context) ([]models.EnrollmentKey, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, name, key_prefix, is_active, auto_approve, usage_count, created_at, expires_at
		FROM enrollment_keys
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []models.EnrollmentKey
	for rows.Next() {
		var key models.EnrollmentKey
		err := rows.Scan(
			&key.ID,
			&key.Name,
			&key.KeyPrefix,
			&key.IsActive,
			&key.AutoApprove,
			&key.UsageCount,
			&key.CreatedAt,
			&key.ExpiresAt,
		)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}

	return keys, nil
}

// GetByID returns an enrollment key by ID
func (s *EnrollmentService) GetByID(ctx context.Context, id int64) (*models.EnrollmentKey, error) {
	var key models.EnrollmentKey
	err := s.db.QueryRow(ctx, `
		SELECT id, name, key_prefix, is_active, auto_approve, usage_count, created_at, expires_at
		FROM enrollment_keys
		WHERE id = $1
	`, id).Scan(
		&key.ID,
		&key.Name,
		&key.KeyPrefix,
		&key.IsActive,
		&key.AutoApprove,
		&key.UsageCount,
		&key.CreatedAt,
		&key.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &key, nil
}

// ValidateKey validates an enrollment key and returns the enrollment key record if valid
func (s *EnrollmentService) ValidateKey(ctx context.Context, key string) (*models.EnrollmentKey, error) {
	// Validate format
	if !auth.ValidateEnrollmentKey(key) {
		return nil, errors.New("invalid key format")
	}

	// Hash the provided key
	keyHash := auth.HashKey(key)

	var enrollmentKey models.EnrollmentKey
	err := s.db.QueryRow(ctx, `
		SELECT id, name, key_prefix, is_active, auto_approve, usage_count, created_at, expires_at
		FROM enrollment_keys
		WHERE key_hash = $1
	`, keyHash).Scan(
		&enrollmentKey.ID,
		&enrollmentKey.Name,
		&enrollmentKey.KeyPrefix,
		&enrollmentKey.IsActive,
		&enrollmentKey.AutoApprove,
		&enrollmentKey.UsageCount,
		&enrollmentKey.CreatedAt,
		&enrollmentKey.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("invalid enrollment key")
		}
		return nil, err
	}

	// Check if active
	if !enrollmentKey.IsActive {
		return nil, errors.New("enrollment key is not active")
	}

	// Check expiration
	if enrollmentKey.ExpiresAt != nil && time.Now().After(*enrollmentKey.ExpiresAt) {
		return nil, errors.New("enrollment key has expired")
	}

	return &enrollmentKey, nil
}

// IncrementUsageCount increments the usage count of an enrollment key
func (s *EnrollmentService) IncrementUsageCount(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `
		UPDATE enrollment_keys
		SET usage_count = usage_count + 1
		WHERE id = $1
	`, id)
	return err
}

// Update updates an enrollment key
func (s *EnrollmentService) Update(ctx context.Context, id int64, name string, isActive bool, autoApprove bool, expiresAt *time.Time) (*models.EnrollmentKey, error) {
	var key models.EnrollmentKey
	err := s.db.QueryRow(ctx, `
		UPDATE enrollment_keys
		SET name = $2, is_active = $3, auto_approve = $4, expires_at = $5
		WHERE id = $1
		RETURNING id, name, key_prefix, is_active, auto_approve, usage_count, created_at, expires_at
	`, id, name, isActive, autoApprove, expiresAt).Scan(
		&key.ID,
		&key.Name,
		&key.KeyPrefix,
		&key.IsActive,
		&key.AutoApprove,
		&key.UsageCount,
		&key.CreatedAt,
		&key.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}

	return &key, nil
}

// Delete deletes an enrollment key
func (s *EnrollmentService) Delete(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM enrollment_keys WHERE id = $1`, id)
	return err
}

// SetActive activates or deactivates an enrollment key
func (s *EnrollmentService) SetActive(ctx context.Context, id int64, isActive bool) error {
	_, err := s.db.Exec(ctx, `
		UPDATE enrollment_keys
		SET is_active = $2
		WHERE id = $1
	`, id, isActive)
	return err
}
