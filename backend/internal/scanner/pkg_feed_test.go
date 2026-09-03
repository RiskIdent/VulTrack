package scanner_test

// Integration coverage for Canonical's package vulnerability feed as a scan
// source, alongside the OVAL sources. Uses the same throwaway PostgreSQL as
// TestOVALPipeline* (see oval_pipeline_test.go for the setup command).

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/oval"
	"github.com/vultrack/vultrack/internal/scanner"
	"github.com/vultrack/vultrack/internal/services"
)

// pkgFeedFixture mirrors com.ubuntu.noble.pkg.json and covers, in order:
//
//   - openssl: a fix that applies to one installed binary and not the other,
//     with the pocket the fix comes from.
//   - bluez: a binary package (bluez-tests) that the OVAL feed does not
//     enumerate at all — the gap this source exists to close.
//   - php-symfony: fixed in a source version that no longer builds the
//     installed binary (a package transition), which has no version to offer.
//   - linux: a kernel source package, which must contribute nothing because
//     OVAL evaluates the kernel against the running kernel instead.
//   - linux-firmware: named like a kernel package but not one, and with an
//     empty binary map, so it is only reachable through the source name the
//     agent reports.
const pkgFeedFixture = `{
  "format": "1",
  "release": "noble",
  "published_at": "2026-08-27T16:19:49Z",
  "packages": {
    "openssl": {
      "source_versions": {
        "3.0.13-0ubuntu3.1": {
          "binary_packages": {"openssl": "3.0.13-0ubuntu3.1", "libssl3t64": "3.0.13-0ubuntu3.1"},
          "pocket": "updates"
        },
        "3.0.13-0ubuntu3.2": {
          "binary_packages": {"openssl": "3.0.13-0ubuntu3.2", "libssl3t64": "3.0.13-0ubuntu3.2"},
          "pocket": "security"
        }
      },
      "cves": {
        "CVE-3000-0001": {"source_fixed_version": "3.0.13-0ubuntu3.2", "status": "fixed"},
        "CVE-3000-0002": {"source_fixed_version": null, "status": "vulnerable"},
        "CVE-3000-0003": {"source_fixed_version": null, "status": "not-vulnerable"}
      }
    },
    "bluez": {
      "source_versions": {
        "5.72-0ubuntu5": {
          "binary_packages": {"bluez": "5.72-0ubuntu5", "bluez-tests": "5.72-0ubuntu5"},
          "pocket": "release"
        }
      },
      "cves": {
        "CVE-3000-0004": {"source_fixed_version": null, "status": "vulnerable"}
      }
    },
    "php-symfony": {
      "source_versions": {
        "6.4.5-1": {
          "binary_packages": {"php-symfony-cache": "6.4.5-1"},
          "pocket": "release"
        },
        "6.4.5-2+esm1": {
          "binary_packages": {"php-symfony-runtime": "6.4.5-2+esm1"},
          "pocket": "esm-apps"
        }
      },
      "cves": {
        "CVE-3000-0005": {"source_fixed_version": "6.4.5-2+esm1", "status": "fixed"}
      }
    },
    "linux": {
      "source_versions": {
        "6.8.0-79.79": {
          "binary_packages": {
            "linux-image-6.8.0-79-generic": "6.8.0-79.79",
            "linux-modules-6.8.0-79-generic": "6.8.0-79.79",
            "linux-libc-dev": "6.8.0-79.79"
          },
          "pocket": "updates"
        }
      },
      "cves": {
        "CVE-3000-0006": {"source_fixed_version": null, "status": "vulnerable"}
      }
    },
    "linux-firmware": {
      "source_versions": {
        "20240318-0ubuntu1": {"binary_packages": {}, "pocket": "release"}
      },
      "cves": {
        "CVE-3000-0007": {"source_fixed_version": null, "status": "vulnerable"}
      }
    }
  },
  "security_issues": {
    "cves": {
      "CVE-3000-0001": {
        "description": "An openssl issue.",
        "published_at": "2026-01-02T00:00:00Z",
        "notes": ["sbeattie> only reachable with a non-default configuration"],
        "cvss_severity": "high",
        "cvss_score": 7.5,
        "ubuntu_priority": "high",
        "mitigation": "Disable the affected cipher suite."
      },
      "CVE-3000-0002": {
        "description": "An unfixed openssl issue.",
        "published_at": "2026-01-03T00:00:00Z",
        "notes": [],
        "cvss_severity": null,
        "cvss_score": null,
        "ubuntu_priority": "low",
        "mitigation": null
      },
      "CVE-3000-0004": {
        "description": "A bluez issue.",
        "published_at": "2026-01-04T00:00:00Z",
        "notes": [],
        "cvss_severity": "medium",
        "cvss_score": 5.0,
        "ubuntu_priority": "medium",
        "mitigation": null
      },
      "CVE-3000-0005": {
        "description": "A symfony issue.",
        "published_at": "2026-01-05T00:00:00Z",
        "notes": [],
        "cvss_severity": "critical",
        "cvss_score": 9.8,
        "ubuntu_priority": "critical",
        "mitigation": null
      },
      "CVE-3000-0006": {
        "description": "A kernel issue.",
        "published_at": "2026-01-06T00:00:00Z",
        "notes": [],
        "cvss_severity": "medium",
        "cvss_score": 5.5,
        "ubuntu_priority": "medium",
        "mitigation": null
      },
      "CVE-3000-0007": {
        "description": "A firmware issue.",
        "published_at": "2026-01-07T00:00:00Z",
        "notes": [],
        "cvss_severity": "low",
        "cvss_score": 3.3,
        "ubuntu_priority": "low",
        "mitigation": null
      }
    },
    "usns": {}
  }
}`

// importPkgFeed stores the fixture as the 'pkg' source for Ubuntu 24.04.
func importPkgFeed(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int64 {
	t.Helper()

	source, err := services.NewOVALService(pool).CreateSource(ctx, "ubuntu", "24.04",
		"pkg", "noble", "https://example.invalid/com.ubuntu.noble.pkg.json.xz", "dpkg")
	if err != nil {
		t.Fatalf("create package feed source: %v", err)
	}

	pkgService := services.NewPkgFeedService(pool)
	stats, err := oval.NewPkgParser(pkgService).ParseAndStore(ctx, source.ID, bytes.NewReader([]byte(pkgFeedFixture)))
	if err != nil {
		t.Fatalf("parse package feed fixture: %v", err)
	}

	if stats.SourcePackages != 5 {
		t.Errorf("imported %d source packages, want 5", stats.SourcePackages)
	}
	// Only "linux" ships linux-image-*/linux-modules-* binaries; linux-firmware
	// must not be mistaken for a kernel package.
	if stats.KernelPackages != 1 {
		t.Errorf("classified %d source packages as kernel, want 1 (only 'linux')", stats.KernelPackages)
	}
	if stats.SkippedStatus != 1 {
		t.Errorf("skipped %d not-vulnerable statuses, want 1", stats.SkippedStatus)
	}
	if stats.CVEStatuses != 6 {
		t.Errorf("imported %d CVE statuses, want 6", stats.CVEStatuses)
	}
	if stats.CVEMetadata != 6 {
		t.Errorf("imported %d CVE metadata entries, want 6", stats.CVEMetadata)
	}
	return source.ID
}

// createServerWithSources inserts a server whose packages carry the source
// package name the agent reads from dpkg.
func createServerWithSources(t *testing.T, ctx context.Context, pool *pgxpool.Pool, kernel string, packages map[string][2]string) int64 {
	t.Helper()

	var serverID int64
	err := pool.QueryRow(ctx, `
		INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager)
		VALUES ('test-pkg-feed', 'ubuntu', '24.04', 'noble', $1, 'amd64', 'dpkg')
		RETURNING id
	`, kernel).Scan(&serverID)
	if err != nil {
		t.Fatalf("insert server: %v", err)
	}

	for name, versionAndSource := range packages {
		_, err := pool.Exec(ctx, `
			INSERT INTO server_packages (server_id, name, version, arch, source_package, first_seen_at, last_seen_at)
			VALUES ($1, $2, $3, 'amd64', NULLIF($4, ''), NOW(), NOW())
		`, serverID, name, versionAndSource[0], versionAndSource[1])
		if err != nil {
			t.Fatalf("insert package %s: %v", name, err)
		}
	}
	return serverID
}

func TestPkgFeedFindings(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importPkgFeed(t, ctx, pool)

	serverID := createServerWithSources(t, ctx, pool, "6.8.0-79-generic", map[string][2]string{
		// Outdated -> a fix from the security pocket applies.
		"openssl": {"3.0.13-0ubuntu3.1", "openssl"},
		// Already at the fixed version -> only the unfixed CVE remains.
		"libssl3t64": {"3.0.13-0ubuntu3.2", "openssl"},
		// The binary the OVAL feed never enumerates.
		"bluez-tests": {"5.72-0ubuntu5", "bluez"},
		// The fixing source version no longer builds this binary.
		"php-symfony-cache": {"6.4.5-1", "php-symfony"},
		// Kernel packages must contribute nothing from this source.
		"linux-image-6.8.0-79-generic": {"6.8.0-79.79", "linux"},
		"linux-libc-dev":               {"6.8.0-79.79", "linux"},
		// Reachable only through the agent-reported source name.
		"linux-firmware": {"20240318-0ubuntu1", "linux-firmware"},
	})

	if _, err := scanner.NewScanner(pool, nil, services.NewPkgFeedService(pool)).ScanServer(ctx, serverID); err != nil {
		t.Fatalf("scan server: %v", err)
	}

	assertFindings(t, activeFindings(t, ctx, pool, serverID), []findingRow{
		{CVEID: "CVE-3000-0001", Package: "openssl", FixState: "fix_available", FixedIn: "3.0.13-0ubuntu3.2"},
		{CVEID: "CVE-3000-0002", Package: "openssl", FixState: "affected"},
		{CVEID: "CVE-3000-0002", Package: "libssl3t64", FixState: "affected"},
		{CVEID: "CVE-3000-0004", Package: "bluez-tests", FixState: "affected"},
		// Package transition: affected, but there is no binary version to install.
		{CVEID: "CVE-3000-0005", Package: "php-symfony-cache", FixState: "affected"},
		{CVEID: "CVE-3000-0007", Package: "linux-firmware", FixState: "affected"},
		// CVE-3000-0001 is not reported for libssl3t64: it is already patched.
		// CVE-3000-0006 is not reported at all: kernel source package.
	})
}

func TestPkgFeedPocketAndSeverity(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importPkgFeed(t, ctx, pool)

	serverID := createServerWithSources(t, ctx, pool, "6.8.0-79-generic", map[string][2]string{
		"openssl":             {"3.0.13-0ubuntu3.1", "openssl"},
		"php-symfony-runtime": {"6.4.5-1", "php-symfony"},
	})

	if _, err := scanner.NewScanner(pool, nil, services.NewPkgFeedService(pool)).ScanServer(ctx, serverID); err != nil {
		t.Fatalf("scan server: %v", err)
	}

	var pocket, severity, sourceType string
	err := pool.QueryRow(ctx, `
		SELECT COALESCE(fix_pocket, ''), COALESCE(severity, ''), COALESCE(source_type, '')
		FROM findings WHERE server_id = $1 AND cve_id = 'CVE-3000-0001' AND package_name = 'openssl'
	`, serverID).Scan(&pocket, &severity, &sourceType)
	if err != nil {
		t.Fatalf("query openssl finding: %v", err)
	}
	if pocket != "security" {
		t.Errorf("fix_pocket = %q, want \"security\"", pocket)
	}
	if severity != "high" {
		t.Errorf("severity = %q, want \"high\" (from ubuntu_priority)", severity)
	}
	if sourceType != "pkg" {
		t.Errorf("source_type = %q, want \"pkg\"", sourceType)
	}

	// An esm-apps pocket is the signal that the fix needs an Ubuntu Pro
	// subscription, which is the whole reason the pocket is stored.
	err = pool.QueryRow(ctx, `
		SELECT COALESCE(fix_pocket, '')
		FROM findings WHERE server_id = $1 AND cve_id = 'CVE-3000-0005' AND package_name = 'php-symfony-runtime'
	`, serverID).Scan(&pocket)
	if err != nil {
		t.Fatalf("query symfony finding: %v", err)
	}
	if pocket != "esm-apps" {
		t.Errorf("fix_pocket = %q, want \"esm-apps\"", pocket)
	}
}

// TestPkgFeedResolvesSourceWithoutAgentHint covers hosts whose agent does not
// report source packages: the source is then resolved through the feed's own
// binary -> source mapping.
func TestPkgFeedResolvesSourceWithoutAgentHint(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importPkgFeed(t, ctx, pool)

	serverID := createServerWithSources(t, ctx, pool, "6.8.0-79-generic", map[string][2]string{
		"openssl":     {"3.0.13-0ubuntu3.1", ""},
		"bluez-tests": {"5.72-0ubuntu5", ""},
		// linux-firmware ships no binary list in the feed, so without the agent's
		// source name it cannot be resolved — and must not produce a finding
		// rather than a wrong one.
		"linux-firmware": {"20240318-0ubuntu1", ""},
	})

	if _, err := scanner.NewScanner(pool, nil, services.NewPkgFeedService(pool)).ScanServer(ctx, serverID); err != nil {
		t.Fatalf("scan server: %v", err)
	}

	assertFindings(t, activeFindings(t, ctx, pool, serverID), []findingRow{
		{CVEID: "CVE-3000-0001", Package: "openssl", FixState: "fix_available", FixedIn: "3.0.13-0ubuntu3.2"},
		{CVEID: "CVE-3000-0002", Package: "openssl", FixState: "affected"},
		{CVEID: "CVE-3000-0004", Package: "bluez-tests", FixState: "affected"},
	})
}

// TestPkgFeedDoesNotOverrideOVAL checks the precedence rule: the feed cannot
// express will_not_fix or deferred, so it must not overwrite a richer OVAL
// finding for the same CVE and package.
func TestPkgFeedDoesNotOverrideOVAL(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importPkgFeed(t, ctx, pool)

	serverID := createServerWithSources(t, ctx, pool, "6.8.0-79-generic", map[string][2]string{
		"openssl": {"3.0.13-0ubuntu3.1", "openssl"},
	})

	// A pre-existing USN finding, as an OVAL scan would have written it.
	_, err := pool.Exec(ctx, `
		INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state,
		                      fixed_in, severity, source_type, first_seen_at, last_seen_at)
		VALUES ($1, 'CVE-3000-0002', 'openssl', '3.0.13-0ubuntu3.1', 'will_not_fix',
		        '', 'negligible', 'usn', NOW(), NOW())
	`, serverID)
	if err != nil {
		t.Fatalf("insert USN finding: %v", err)
	}

	if _, err := scanner.NewScanner(pool, nil, services.NewPkgFeedService(pool)).ScanServer(ctx, serverID); err != nil {
		t.Fatalf("scan server: %v", err)
	}

	var fixState, severity, sourceType string
	err = pool.QueryRow(ctx, `
		SELECT COALESCE(fix_state, ''), COALESCE(severity, ''), COALESCE(source_type, '')
		FROM findings WHERE server_id = $1 AND cve_id = 'CVE-3000-0002' AND package_name = 'openssl'
	`, serverID).Scan(&fixState, &severity, &sourceType)
	if err != nil {
		t.Fatalf("query finding: %v", err)
	}

	if sourceType != "usn" || fixState != "will_not_fix" || severity != "negligible" {
		t.Errorf("the package feed downgraded a USN finding: source_type=%q fix_state=%q severity=%q",
			sourceType, fixState, severity)
	}

	// The USN finding still has to count as seen, or the scan would resolve it.
	var resolved *string
	if err := pool.QueryRow(ctx, `
		SELECT resolved_at::text FROM findings
		WHERE server_id = $1 AND cve_id = 'CVE-3000-0002' AND package_name = 'openssl'
	`, serverID).Scan(&resolved); err != nil {
		t.Fatalf("query resolved_at: %v", err)
	}
	if resolved != nil {
		t.Errorf("finding was resolved despite still being reported: resolved_at=%v", *resolved)
	}
}

// TestPkgFeedPocketSurvivesPrecedence covers the other half of the precedence
// rule: the pocket is information only the package feed has, so it must reach
// the row even when a stronger source owns the rest of it. Nearly every
// fixable CVE the feed knows is also covered by OVAL, so without this the
// pocket would almost never be visible.
func TestPkgFeedPocketSurvivesPrecedence(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importPkgFeed(t, ctx, pool)

	serverID := createServerWithSources(t, ctx, pool, "6.8.0-79-generic", map[string][2]string{
		"openssl":             {"3.0.13-0ubuntu3.1", "openssl"},
		"php-symfony-runtime": {"6.4.5-1", "php-symfony"},
	})

	// Both CVEs already have a USN finding, as an OVAL scan would have left them.
	for _, f := range []struct{ cve, pkg, version string }{
		{"CVE-3000-0001", "openssl", "3.0.13-0ubuntu3.1"},
		{"CVE-3000-0005", "php-symfony-runtime", "6.4.5-1"},
	} {
		_, err := pool.Exec(ctx, `
			INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state,
			                      fixed_in, severity, source_type, first_seen_at, last_seen_at)
			VALUES ($1, $2, $3, $4, 'fix_available', 'from-usn', 'critical', 'usn', NOW(), NOW())
		`, serverID, f.cve, f.pkg, f.version)
		if err != nil {
			t.Fatalf("insert USN finding for %s: %v", f.cve, err)
		}
	}

	if _, err := scanner.NewScanner(pool, nil, services.NewPkgFeedService(pool)).ScanServer(ctx, serverID); err != nil {
		t.Fatalf("scan server: %v", err)
	}

	for _, want := range []struct{ cve, pkg, pocket string }{
		{"CVE-3000-0001", "openssl", "security"},
		{"CVE-3000-0005", "php-symfony-runtime", "esm-apps"},
	} {
		var pocket, fixedIn, sourceType string
		err := pool.QueryRow(ctx, `
			SELECT COALESCE(fix_pocket, ''), COALESCE(fixed_in, ''), COALESCE(source_type, '')
			FROM findings WHERE server_id = $1 AND cve_id = $2 AND package_name = $3
		`, serverID, want.cve, want.pkg).Scan(&pocket, &fixedIn, &sourceType)
		if err != nil {
			t.Fatalf("query %s: %v", want.cve, err)
		}
		if pocket != want.pocket {
			t.Errorf("%s: fix_pocket = %q, want %q", want.cve, pocket, want.pocket)
		}
		// The stronger source still owns everything else.
		if sourceType != "usn" || fixedIn != "from-usn" {
			t.Errorf("%s: the package feed took over the row: source_type=%q fixed_in=%q",
				want.cve, sourceType, fixedIn)
		}
	}
}

// TestPkgFeedClearsStalePocket covers the inverse: once the feed no longer
// offers a fix, the pocket it wrote earlier must not linger.
func TestPkgFeedClearsStalePocket(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importPkgFeed(t, ctx, pool)

	serverID := createServerWithSources(t, ctx, pool, "6.8.0-79-generic", map[string][2]string{
		"openssl": {"3.0.13-0ubuntu3.1", "openssl"},
	})
	s := scanner.NewScanner(pool, nil, services.NewPkgFeedService(pool))

	if _, err := s.ScanServer(ctx, serverID); err != nil {
		t.Fatalf("first scan: %v", err)
	}

	// CVE-3000-0002 has no fix, so it must carry no pocket at all.
	var pocket *string
	if err := pool.QueryRow(ctx, `
		SELECT fix_pocket FROM findings
		WHERE server_id = $1 AND cve_id = 'CVE-3000-0002' AND package_name = 'openssl'
	`, serverID).Scan(&pocket); err != nil {
		t.Fatalf("query unfixed finding: %v", err)
	}
	if pocket != nil {
		t.Errorf("an unfixed finding carries a pocket: %q", *pocket)
	}

	// Plant a stale pocket and confirm the next scan clears it.
	if _, err := pool.Exec(ctx, `
		UPDATE findings SET fix_pocket = 'esm-apps'
		WHERE server_id = $1 AND cve_id = 'CVE-3000-0002' AND package_name = 'openssl'
	`, serverID); err != nil {
		t.Fatalf("plant stale pocket: %v", err)
	}
	if _, err := s.ScanServer(ctx, serverID); err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT fix_pocket FROM findings
		WHERE server_id = $1 AND cve_id = 'CVE-3000-0002' AND package_name = 'openssl'
	`, serverID).Scan(&pocket); err != nil {
		t.Fatalf("query after rescan: %v", err)
	}
	if pocket != nil {
		t.Errorf("stale pocket survived a rescan: %q", *pocket)
	}
}

// TestPkgFeedOptional checks that a scanner without the feed service, or a
// server whose release has no feed source, behaves exactly as before.
func TestPkgFeedOptional(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importPkgFeed(t, ctx, pool)

	serverID := createServerWithSources(t, ctx, pool, "6.8.0-79-generic", map[string][2]string{
		"openssl": {"3.0.13-0ubuntu3.1", "openssl"},
	})

	// Feed service not wired up: the source is skipped, the scan still succeeds.
	if _, err := scanner.NewScanner(pool, nil, nil).ScanServer(ctx, serverID); err != nil {
		t.Fatalf("scan without the feed service must still succeed: %v", err)
	}
	assertFindings(t, activeFindings(t, ctx, pool, serverID), nil)

	// Source disabled: same result.
	if _, err := pool.Exec(ctx, `UPDATE oval_sources SET is_enabled = false WHERE source_type = 'pkg'`); err != nil {
		t.Fatalf("disable source: %v", err)
	}
	if _, err := scanner.NewScanner(pool, nil, services.NewPkgFeedService(pool)).ScanServer(ctx, serverID); err != nil {
		t.Fatalf("scan with a disabled feed source: %v", err)
	}
	assertFindings(t, activeFindings(t, ctx, pool, serverID), nil)
}

// TestEnsureOptionalSources covers how an existing installation picks the feed
// up: releases that already have OVAL sources gain a 'pkg' source on the next
// start, without their enabled state being touched, and without duplicates on
// repeated starts.
func TestEnsureOptionalSources(t *testing.T) {
	pool, ctx := setupPipeline(t)
	ovalService := services.NewOVALService(pool)

	// An installation as it looks before the upgrade: USN + CVE only, and one
	// release the operator had deliberately disabled.
	_, err := pool.Exec(ctx, `
		INSERT INTO oval_sources (distribution, version, source_type, codename, url, package_manager, is_enabled)
		VALUES ('ubuntu', '24.04', 'usn', 'noble', 'https://example.invalid', 'dpkg', true),
		       ('ubuntu', '24.04', 'cve', 'noble', 'https://example.invalid', 'dpkg', true),
		       ('ubuntu', '22.04', 'usn', 'jammy', 'https://example.invalid', 'dpkg', false)
	`)
	if err != nil {
		t.Fatalf("insert pre-upgrade sources: %v", err)
	}

	created, err := ovalService.EnsureOptionalSources(ctx)
	if err != nil {
		t.Fatalf("ensure optional sources: %v", err)
	}
	if created != 2 {
		t.Errorf("created %d sources, want 2 (one per enabled release)", created)
	}

	// Running again must not create duplicates.
	created, err = ovalService.EnsureOptionalSources(ctx)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if created != 0 {
		t.Errorf("second run created %d sources, want 0", created)
	}

	// The URL must be built from the distribution's template and codename.
	var url string
	if err := pool.QueryRow(ctx, `
		SELECT url FROM oval_sources WHERE version = '24.04' AND source_type = 'pkg'
	`).Scan(&url); err != nil {
		t.Fatalf("query new source: %v", err)
	}
	const want = "https://security-metadata.canonical.com/oval/com.ubuntu.noble.pkg.json.xz"
	if url != want {
		t.Errorf("url = %q, want %q", url, want)
	}

	// A release the operator had turned off keeps its own state; only the new
	// source of that release is added, and disabling it stays possible.
	var enabled bool
	if err := pool.QueryRow(ctx, `
		SELECT is_enabled FROM oval_sources WHERE version = '22.04' AND source_type = 'usn'
	`).Scan(&enabled); err != nil {
		t.Fatalf("query disabled source: %v", err)
	}
	if enabled {
		t.Error("an existing source's enabled state was changed")
	}
}

// TestPkgFeedBackfillsCVECatalog covers the second gap the feed closes: CVSS
// scores and descriptions that VulTrack otherwise waits for the NVD sync to
// deliver. Values NVD already provides must be left alone.
func TestPkgFeedBackfillsCVECatalog(t *testing.T) {
	pool, ctx := setupPipeline(t)
	sourceID := importPkgFeed(t, ctx, pool)

	// An existing NVD row that must survive the backfill unchanged.
	_, err := pool.Exec(ctx, `
		INSERT INTO cve_catalog (cve_id, description, cvss3_score, cvss3_severity)
		VALUES ('CVE-3000-0001', 'NVD description', 9.1, 'critical')
	`)
	if err != nil {
		t.Fatalf("insert NVD row: %v", err)
	}

	pkgService := services.NewPkgFeedService(pool)
	if _, err := pkgService.BackfillCVECatalog(ctx, sourceID); err != nil {
		t.Fatalf("backfill: %v", err)
	}

	var description, severity string
	var score *float64
	err = pool.QueryRow(ctx, `
		SELECT description, cvss3_score, COALESCE(cvss3_severity, '')
		FROM cve_catalog WHERE cve_id = 'CVE-3000-0001'
	`).Scan(&description, &score, &severity)
	if err != nil {
		t.Fatalf("query backfilled NVD row: %v", err)
	}
	if description != "NVD description" || score == nil || *score != 9.1 || severity != "critical" {
		t.Errorf("the backfill overwrote NVD data: description=%q score=%v severity=%q",
			description, score, severity)
	}

	// A CVE NVD has not delivered yet gets the feed's values.
	err = pool.QueryRow(ctx, `
		SELECT description, cvss3_score, COALESCE(cvss3_severity, '')
		FROM cve_catalog WHERE cve_id = 'CVE-3000-0005'
	`).Scan(&description, &score, &severity)
	if err != nil {
		t.Fatalf("query newly backfilled row: %v", err)
	}
	if description != "A symfony issue." || score == nil || *score != 9.8 || severity != "critical" {
		t.Errorf("feed values were not backfilled: description=%q score=%v severity=%q",
			description, score, severity)
	}

	// A CVE with neither a score nor a description in the feed is not inserted.
	var exists bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM cve_catalog WHERE cve_id = 'CVE-3000-9999')
	`).Scan(&exists); err != nil {
		t.Fatalf("query absent row: %v", err)
	}
	if exists {
		t.Error("the backfill invented a CVE the feed does not describe")
	}
}
