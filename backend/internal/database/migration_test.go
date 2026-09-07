package database_test

// Covers the repair of an exhausted findings_id_seq.
//
// findings.id was SERIAL, and INSERT ... ON CONFLICT DO UPDATE evaluates the
// column default before it detects the conflict, so every upsert consumed a
// sequence value even when it only updated an existing row. The scanner upserts
// every finding of every server on every scan, so the sequence advanced by
// thousands per scan while the row count barely moved. On a production instance
// it reached the 32-bit ceiling after a few months, at which point no finding
// could be written at all.
//
// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/database"
	"github.com/vultrack/vultrack/internal/testdb"
)

// upsertFinding performs the same shape of write the scanner does.
func upsertFinding(ctx context.Context, pool *pgxpool.Pool, cveID string) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO findings (server_id, cve_id, package_name, first_seen_at, last_seen_at)
		VALUES ($1, $2, 'openssl', NOW(), NOW())
		ON CONFLICT (server_id, cve_id, package_name)
		DO UPDATE SET last_seen_at = NOW()
	`, nil, cveID)
	return err
}

func findingsIDType(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	var dataType string
	err := pool.QueryRow(ctx, `
		SELECT data_type FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name = 'findings' AND column_name = 'id'
	`).Scan(&dataType)
	if err != nil {
		t.Fatalf("read findings.id type: %v", err)
	}
	return dataType
}

// TestFreshSchemaUsesBigintFindingID keeps new installations off the 32-bit
// sequence in the first place.
func TestFreshSchemaUsesBigintFindingID(t *testing.T) {
	pool, ctx := testdb.Setup(t, "migration_tests")

	if got := findingsIDType(t, ctx, pool); got != "bigint" {
		t.Errorf("findings.id is %q on a fresh schema, want \"bigint\"", got)
	}

	// pg_sequences is the same view the sequence-headroom metric reads.
	var dataType string
	var maxValue int64
	err := pool.QueryRow(ctx, `
		SELECT data_type::text, max_value FROM pg_sequences
		WHERE schemaname = current_schema() AND sequencename = 'findings_id_seq'
	`).Scan(&dataType, &maxValue)
	if err != nil {
		t.Fatalf("read findings_id_seq: %v", err)
	}
	if dataType != "bigint" {
		t.Errorf("findings_id_seq is a %s sequence, want bigint", dataType)
	}
	if maxValue != 9223372036854775807 {
		t.Errorf("findings_id_seq max is %d, want the bigint maximum", maxValue)
	}
}

// TestMigrationRepairsExhaustedFindingSequence reproduces the production state —
// a 32-bit sequence driven to its ceiling — and checks that running the
// migration makes writes work again.
func TestMigrationRepairsExhaustedFindingSequence(t *testing.T) {
	pool, ctx := testdb.Setup(t, "migration_repair_tests")

	// Put the schema back the way affected instances have it.
	_, err := pool.Exec(ctx, `
		ALTER TABLE findings ALTER COLUMN id TYPE integer;
		ALTER SEQUENCE findings_id_seq AS integer MAXVALUE 2147483647;
		SELECT setval('findings_id_seq', 2147483647);
	`)
	if err != nil {
		t.Fatalf("downgrade findings.id to the pre-migration state: %v", err)
	}
	if got := findingsIDType(t, ctx, pool); got != "integer" {
		t.Fatalf("could not reproduce the pre-migration state: findings.id is %q", got)
	}

	// An upsert that would only update still asks for a sequence value, so even
	// existing findings can no longer be touched.
	if err := upsertFinding(ctx, pool, "CVE-2000-0001"); err == nil {
		t.Fatal("expected the exhausted sequence to reject the upsert")
	}

	if err := database.Migrate(pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	if got := findingsIDType(t, ctx, pool); got != "bigint" {
		t.Errorf("findings.id is %q after the migration, want \"bigint\"", got)
	}
	if err := upsertFinding(ctx, pool, "CVE-2000-0001"); err != nil {
		t.Fatalf("upsert still fails after the migration: %v", err)
	}
	// And a genuinely new row, which is what actually draws from the sequence.
	if err := upsertFinding(ctx, pool, "CVE-2000-0002"); err != nil {
		t.Fatalf("insert of a new finding fails after the migration: %v", err)
	}

	var id int64
	if err := pool.QueryRow(ctx, `
		SELECT id FROM findings WHERE cve_id = 'CVE-2000-0002'
	`).Scan(&id); err != nil {
		t.Fatalf("read the new finding: %v", err)
	}
	if id <= 2147483647 {
		t.Errorf("new finding got id %d, expected the sequence to continue past the 32-bit ceiling", id)
	}
}

// TestMigrationIsIdempotent guards the guard: the widening rewrites the table
// under an ACCESS EXCLUSIVE lock, so it must not run on every startup.
func TestMigrationIsIdempotent(t *testing.T) {
	pool, ctx := testdb.Setup(t, "migration_idempotent_tests")

	for i := 0; i < 2; i++ {
		if err := database.Migrate(pool); err != nil {
			t.Fatalf("migrate run %d: %v", i+2, err)
		}
	}
	if got := findingsIDType(t, ctx, pool); got != "bigint" {
		t.Errorf("findings.id is %q after repeated migrations, want \"bigint\"", got)
	}
	if err := upsertFinding(ctx, pool, "CVE-2000-0003"); err != nil {
		t.Fatalf("upsert after repeated migrations: %v", err)
	}
}
