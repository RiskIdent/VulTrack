package services_test

// Package usage observation for R-UNUSED: last time in use per package, and a
// gap-free observation period that missing, truncated or late reports end.
//
// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

func TestPackageUsage(t *testing.T) {
	pool, ctx := testdb.Setup(t, "package_usage_tests")
	rf := services.NewRuntimeFactsService(pool)
	var id int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager)
		VALUES ('pu', 'ubuntu', '24.04', 'noble', '6.8.0', 'amd64', 'dpkg') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	ingest := func(runtime string) {
		t.Helper()
		if _, err := rf.Ingest(ctx, id, json.RawMessage(runtime)); err != nil {
			t.Fatal(err)
		}
	}
	usage := func() *services.PackageUsage {
		t.Helper()
		u, err := services.GetPackageUsage(ctx, pool, id)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	inUse := func(pkgs ...string) string {
		entries := []map[string]any{}
		for _, p := range pkgs {
			entries = append(entries, map[string]any{"package": p, "processes": []string{"x"}})
		}
		b, _ := json.Marshal(map[string]any{"schemaVersion": 1, "packagesInUse": entries})
		return string(b)
	}

	if u := usage(); u.ObservedSince != nil || u.ObservedFor != 0 {
		t.Fatalf("no reports yet: %+v", u)
	}
	ingest(inUse("libssl3t64", "nginx-core"))
	u := usage()
	if u.ObservedSince == nil || len(u.LastInUse) != 2 {
		t.Fatalf("after the first report: %+v", u)
	}

	// Observation continues across reports; a package seen earlier keeps its
	// last-in-use time when it is no longer in use.
	exec(`UPDATE package_usage_observation SET observed_since = NOW() - interval '10 days', last_observed_at = NOW() - interval '1 hour'`)
	exec(`UPDATE package_usage SET last_in_use_at = NOW() - interval '9 days' WHERE package = 'nginx-core'`)
	ingest(inUse("libssl3t64"))
	u = usage()
	if u.ObservedFor < 9*24*time.Hour || u.LastInUse["nginx-core"] < 8*24*time.Hour || u.LastInUse["libssl3t64"] > time.Hour {
		t.Errorf("continuing observation: for %v, last in use %v", u.ObservedFor, u.LastInUse)
	}

	// A gap of more than six hours restarts the observation.
	exec(`UPDATE package_usage_observation SET last_observed_at = NOW() - interval '7 hours'`)
	if u = usage(); u.ObservedFor != 0 {
		t.Errorf("a stale observation must not count: %v", u.ObservedFor)
	}
	ingest(inUse("libssl3t64"))
	if u = usage(); u.ObservedFor > time.Minute {
		t.Errorf("after a gap the observation restarts: %v", u.ObservedFor)
	}

	// Truncated, missing or no runtime at all: observation ends.
	for name, rt := range map[string]string{
		"truncated":  `{"schemaVersion": 1, "packagesInUse": [{"package": "a", "processes": ["x"]}], "truncated": ["packagesInUse"]}`,
		"missing":    `{"schemaVersion": 1, "listeners": []}`,
		"no runtime": ``,
	} {
		exec(`UPDATE package_usage_observation SET observed_since = NOW() - interval '20 days', last_observed_at = NOW()`)
		ingest(rt)
		if u = usage(); u.ObservedSince != nil || u.ObservedFor != 0 {
			t.Errorf("%s: observation must end, got %+v", name, u)
		}
	}

	// The server's runtime API shows it.
	ingest(inUse("libssl3t64"))
	rt, err := rf.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if rt.PackageUsage == nil || rt.PackageUsage.TrackedPackages != 2 {
		t.Errorf("runtime API: %+v", rt.PackageUsage)
	}
}
