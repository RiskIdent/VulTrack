package database

import (
	"context"
	_ "embed"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/config"
)

//go:embed schema.sql
var schemaSQL string

//go:embed seed.sql
var seedSQL string

// Connect establishes a connection pool to the PostgreSQL database
func Connect(cfg *config.Config) (*pgxpool.Pool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	poolConfig, err := pgxpool.ParseConfig(cfg.DatabaseURL())
	if err != nil {
		return nil, err
	}

	// Configure connection pool
	poolConfig.MaxConns = 50
	poolConfig.MinConns = 5
	poolConfig.MaxConnLifetime = time.Hour
	poolConfig.MaxConnIdleTime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, err
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		return nil, err
	}

	log.Info().Msg("Successfully connected to PostgreSQL database")
	return pool, nil
}

// Migrate runs database migrations by executing the embedded SQL files
func Migrate(db *pgxpool.Pool) error {
	ctx := context.Background()

	// Execute schema SQL
	log.Info().Msg("Applying database schema...")
	if _, err := db.Exec(ctx, schemaSQL); err != nil {
		log.Error().Err(err).Msg("Failed to apply database schema")
		return err
	}
	log.Info().Msg("Database schema applied successfully")

	// Execute seed SQL
	log.Info().Msg("Applying seed data...")
	if _, err := db.Exec(ctx, seedSQL); err != nil {
		log.Error().Err(err).Msg("Failed to apply seed data")
		return err
	}
	log.Info().Msg("Seed data applied successfully")

	log.Info().Msg("Database migrations completed successfully")
	return nil
}
