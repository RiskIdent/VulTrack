// Package testdb bootstraps a throwaway PostgreSQL schema for the DB-backed
// tests. It is imported from _test files only.
//
// Each test package gets its own schema rather than sharing `public`, because
// `go test ./...` runs packages in parallel and a shared schema means one
// package drops the tables another one is using.
//
// Start a database with:
//
//	docker run -d --rm -e POSTGRES_PASSWORD=test -e POSTGRES_USER=test \
//	    -e POSTGRES_DB=test -p 55432:5432 postgres:16-alpine
//	export VULTRACK_TEST_DATABASE_URL='postgres://test:test@127.0.0.1:55432/test'
//
// Tests skip when that variable is unset.
package testdb

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/database"
)

// DatabaseURLEnv is the environment variable holding the test database DSN.
const DatabaseURLEnv = "VULTRACK_TEST_DATABASE_URL"

// safeSchemaName guards the schema name, which cannot be parameterised in DDL.
var safeSchemaName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}$`)

// Setup returns a pool bound to a freshly migrated schema named after the test
// package, and skips the test when no test database is configured.
//
// The schema is dropped and recreated, so every test starts from a known state.
func Setup(t *testing.T, schema string) (*pgxpool.Pool, context.Context) {
	t.Helper()

	if !safeSchemaName.MatchString(schema) {
		t.Fatalf("invalid test schema name %q", schema)
	}

	dsn := os.Getenv(DatabaseURLEnv)
	if dsn == "" {
		t.Skipf("%s not set; skipping database-backed test", DatabaseURLEnv)
	}

	ctx := context.Background()

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse %s: %v", DatabaseURLEnv, err)
	}
	// Every connection of this pool resolves unqualified names in our own
	// schema, so the embedded schema.sql needs no changes.
	config.ConnConfig.RuntimeParams["search_path"] = schema

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect to the test database: %v", err)
	}
	t.Cleanup(pool.Close)

	if _, err := pool.Exec(ctx, fmt.Sprintf(
		"DROP SCHEMA IF EXISTS %s CASCADE; CREATE SCHEMA %s", schema, schema,
	)); err != nil {
		t.Fatalf("reset schema %s: %v", schema, err)
	}

	if err := database.Migrate(pool); err != nil {
		t.Fatalf("migrate schema %s: %v", schema, err)
	}

	return pool, ctx
}
