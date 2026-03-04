package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// SessionIDLength is the number of random bytes for the session ID (hex-encoded = 2x chars).
	SessionIDLength = 32
	// CookieName is the name of the session cookie sent to the client.
	CookieName = "vultrack_session"
	// DefaultSessionDuration is how long a session stays valid.
	DefaultSessionDuration = 24 * time.Hour
)

// Store handles session creation, lookup, and deletion in the database.
type Store struct {
	db       *pgxpool.Pool
	duration time.Duration
}

// NewStore creates a new session store.
func NewStore(db *pgxpool.Pool, duration time.Duration) *Store {
	if duration <= 0 {
		duration = DefaultSessionDuration
	}
	return &Store{db: db, duration: duration}
}

// Create generates a new session ID, stores the session in the database, and returns the session ID and expiry.
func (s *Store) Create(ctx context.Context, userID int64) (sessionID string, expiresAt time.Time, err error) {
	b := make([]byte, SessionIDLength)
	if _, err := rand.Read(b); err != nil {
		return "", time.Time{}, err
	}
	sessionID = hex.EncodeToString(b)
	expiresAt = time.Now().Add(s.duration)

	_, err = s.db.Exec(ctx, `
		INSERT INTO sessions (id, user_id, expires_at)
		VALUES ($1, $2, $3)
	`, sessionID, userID, expiresAt)
	if err != nil {
		return "", time.Time{}, err
	}
	return sessionID, expiresAt, nil
}

// Get loads the session by ID. Returns userID and expiry if the session exists and is not expired; otherwise zero values and false.
func (s *Store) Get(ctx context.Context, sessionID string) (userID int64, expiresAt time.Time, ok bool) {
	var exp time.Time
	err := s.db.QueryRow(ctx, `
		SELECT user_id, expires_at FROM sessions
		WHERE id = $1 AND expires_at > NOW()
	`, sessionID).Scan(&userID, &exp)
	if err != nil {
		return 0, time.Time{}, false
	}
	return userID, exp, true
}

// Delete removes the session from the database.
func (s *Store) Delete(ctx context.Context, sessionID string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sessionID)
	return err
}
