package config

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestDatabaseURLEscapesCredentials checks that credentials with URI
// delimiters survive the round trip through pgx's connection-string parser.
// pgx 5.11 ends the userinfo at the first '@', so an unescaped '@' in the
// password would split it and send the rest as the host name.
func TestDatabaseURLEscapesCredentials(t *testing.T) {
	cfg := &Config{
		PostgresUser:     "vul track",
		PostgresPassword: "p@ss/w#rd%41 :?",
		PostgresHost:     "db.internal",
		PostgresPort:     5433,
		PostgresDB:       "vultrack",
	}

	pc, err := pgxpool.ParseConfig(cfg.DatabaseURL())
	if err != nil {
		t.Fatalf("ParseConfig(%q): %v", cfg.DatabaseURL(), err)
	}
	cc := pc.ConnConfig
	if cc.User != cfg.PostgresUser {
		t.Errorf("user = %q, want %q", cc.User, cfg.PostgresUser)
	}
	if cc.Password != cfg.PostgresPassword {
		t.Errorf("password = %q, want %q", cc.Password, cfg.PostgresPassword)
	}
	if cc.Host != cfg.PostgresHost || cc.Port != uint16(cfg.PostgresPort) {
		t.Errorf("host = %s:%d, want %s:%d", cc.Host, cc.Port, cfg.PostgresHost, cfg.PostgresPort)
	}
	if cc.Database != cfg.PostgresDB {
		t.Errorf("database = %q, want %q", cc.Database, cfg.PostgresDB)
	}
}
