package services

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/models"
)

// UserService handles user lookup and OIDC provisioning.
type UserService struct {
	db *pgxpool.Pool
}

// NewUserService creates a new UserService.
func NewUserService(db *pgxpool.Pool) *UserService {
	return &UserService{db: db}
}

// GetByID returns the user by ID, or nil if not found.
func (s *UserService) GetByID(ctx context.Context, id int64) (*models.User, error) {
	var u models.User
	err := s.db.QueryRow(ctx, `
		SELECT id, email, name, is_admin, last_login_at, created_at, updated_at,
		       COALESCE(oidc_subject, ''), COALESCE(oidc_issuer, '')
		FROM users WHERE id = $1
	`, id).Scan(
		&u.ID,
		&u.Email,
		&u.Name,
		&u.IsAdmin,
		&u.LastLoginAt,
		&u.CreatedAt,
		&u.UpdatedAt,
		&u.OIDCSubject,
		&u.OIDCIssuer,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

// GetOrCreateFromOIDC finds a user by (oidc_issuer, oidc_subject) or creates one. Updates last_login_at and applies admin logic:
// if no user in the system has is_admin = true, this user is set (or updated) to admin.
func (s *UserService) GetOrCreateFromOIDC(ctx context.Context, oidcSubject, oidcIssuer, email, name string) (*models.User, error) {
	if oidcSubject == "" || oidcIssuer == "" {
		return nil, nil
	}

	// Prefer email from IdP; fallback for display to preferred_username or name
	if email == "" {
		email = name
	}
	if email == "" {
		email = oidcSubject // last resort so we satisfy NOT NULL
	}

	var u models.User
	err := s.db.QueryRow(ctx, `
		SELECT id, email, name, is_admin, last_login_at, created_at, updated_at,
		       COALESCE(oidc_subject, ''), COALESCE(oidc_issuer, '')
		FROM users
		WHERE oidc_issuer = $1 AND oidc_subject = $2
	`, oidcIssuer, oidcSubject).Scan(
		&u.ID,
		&u.Email,
		&u.Name,
		&u.IsAdmin,
		&u.LastLoginAt,
		&u.CreatedAt,
		&u.UpdatedAt,
		&u.OIDCSubject,
		&u.OIDCIssuer,
	)
	if err == nil {
		// Existing user: update last_login_at and optionally name/email; apply admin logic
		now := time.Now()
		adminCount, _ := s.countAdmins(ctx)
		if adminCount == 0 {
			_, _ = s.db.Exec(ctx, `
				UPDATE users SET last_login_at = $1, name = $2, email = $3, is_admin = true, updated_at = $1 WHERE id = $4
			`, now, name, email, u.ID)
			u.LastLoginAt = &now
			u.Name = name
			u.Email = email
			u.IsAdmin = true
		} else {
			_, _ = s.db.Exec(ctx, `
				UPDATE users SET last_login_at = $1, name = $2, email = $3, updated_at = $1 WHERE id = $4
			`, now, name, email, u.ID)
			u.LastLoginAt = &now
			u.Name = name
			u.Email = email
		}
		return &u, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	// New user: create with admin = true if no admins exist
	adminCount, err := s.countAdmins(ctx)
	if err != nil {
		return nil, err
	}
	isAdmin := adminCount == 0

	err = s.db.QueryRow(ctx, `
		INSERT INTO users (email, name, is_admin, oidc_subject, oidc_issuer, last_login_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, email, name, is_admin, last_login_at, created_at, updated_at
	`, email, name, isAdmin, oidcSubject, oidcIssuer, time.Now()).Scan(
		&u.ID,
		&u.Email,
		&u.Name,
		&u.IsAdmin,
		&u.LastLoginAt,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	u.OIDCSubject = oidcSubject
	u.OIDCIssuer = oidcIssuer
	return &u, nil
}

func (s *UserService) countAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE is_admin = true`).Scan(&n)
	return n, err
}

// List returns all users (for admin UI). OIDC fields are not exposed.
func (s *UserService) List(ctx context.Context) ([]*models.User, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, email, name, is_admin, last_login_at, created_at, updated_at,
		       COALESCE(oidc_subject, ''), COALESCE(oidc_issuer, '')
		FROM users
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(
			&u.ID,
			&u.Email,
			&u.Name,
			&u.IsAdmin,
			&u.LastLoginAt,
			&u.CreatedAt,
			&u.UpdatedAt,
			&u.OIDCSubject,
			&u.OIDCIssuer,
		); err != nil {
			return nil, err
		}
		list = append(list, &u)
	}
	return list, rows.Err()
}

// SetAdmin sets the admin flag for a user. Caller must ensure the current user is an admin.
func (s *UserService) SetAdmin(ctx context.Context, userID int64, isAdmin bool) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET is_admin = $1, updated_at = NOW() WHERE id = $2`, isAdmin, userID)
	return err
}
