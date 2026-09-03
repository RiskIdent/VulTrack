package scanner_test

// Coverage for the kernel flavour cross-check: Ubuntu's uname tests carry no
// architecture predicate and the riscv64 kernel flavour is also called
// "generic", so a criterion for a foreign flavour can match the running kernel.
// Canonical's package feed knows which kernel source package is affected, and
// that verdict decides.
//
// Uses the same throwaway PostgreSQL as the other pipeline tests; see
// oval_pipeline_test.go for the setup command.

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/oval"
	"github.com/vultrack/vultrack/internal/scanner"
	"github.com/vultrack/vultrack/internal/services"
)

// kernelFilterOVALFixture reproduces the collision. tst:9000 is labelled for
// linux-riscv but its pattern matches any 6.8.0-x-generic kernel, exactly as
// oval:com.ubuntu.noble:tst:201245420000460 does in the real feed; tst:9100 is
// the genuine linux criterion. Both fire on 6.8.0-79-generic.
//
//	CVE-4000-0001  riscv criterion only   feed: linux not-vulnerable, riscv vulnerable
//	CVE-4000-0002  linux criterion only   feed: linux vulnerable, riscv not-vulnerable
//	CVE-4000-0003  riscv criterion only   feed: does not track it at all
//	CVE-4000-0004  riscv criterion only   feed: linux fixed in 6.8.0-84.84
const kernelFilterOVALFixture = `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
                  xmlns:ind-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"
                  xmlns:unix-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"
                  xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <generator><product_name>Canonical OVAL Generator</product_name></generator>

  <definitions>
    <definition id="oval:com.ubuntu.noble:def:100" class="inventory" version="1">
      <metadata><title>Check that Ubuntu 24.04 LTS (noble) is installed.</title></metadata>
      <criteria>
        <criterion test_ref="oval:com.ubuntu.noble:tst:100" comment="The host is part of the unix family." />
      </criteria>
    </definition>

    <definition id="oval:com.ubuntu.noble:def:9000" class="vulnerability" version="1">
      <metadata>
        <title>CVE-4000-0001 on Ubuntu 24.04 LTS (noble)</title>
        <reference source="CVE" ref_id="CVE-4000-0001" ref_url="https://ubuntu.com/security/CVE-4000-0001" />
        <advisory><severity>High</severity></advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" comment="Ubuntu 24.04 LTS (noble) is installed" />
        <criteria operator="OR">
          <criterion test_ref="oval:com.ubuntu.noble:tst:9000" comment="Is kernel 'linux-riscv' running?" />
        </criteria>
      </criteria>
    </definition>

    <definition id="oval:com.ubuntu.noble:def:9100" class="vulnerability" version="1">
      <metadata>
        <title>CVE-4000-0002 on Ubuntu 24.04 LTS (noble)</title>
        <reference source="CVE" ref_id="CVE-4000-0002" ref_url="https://ubuntu.com/security/CVE-4000-0002" />
        <advisory><severity>High</severity></advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" comment="Ubuntu 24.04 LTS (noble) is installed" />
        <criteria operator="OR">
          <criterion test_ref="oval:com.ubuntu.noble:tst:9100" comment="Is kernel 'linux' running?" />
        </criteria>
      </criteria>
    </definition>

    <definition id="oval:com.ubuntu.noble:def:9200" class="vulnerability" version="1">
      <metadata>
        <title>CVE-4000-0003 on Ubuntu 24.04 LTS (noble)</title>
        <reference source="CVE" ref_id="CVE-4000-0003" ref_url="https://ubuntu.com/security/CVE-4000-0003" />
        <advisory><severity>Medium</severity></advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" comment="Ubuntu 24.04 LTS (noble) is installed" />
        <criteria operator="OR">
          <criterion test_ref="oval:com.ubuntu.noble:tst:9000" comment="Is kernel 'linux-riscv' running?" />
        </criteria>
      </criteria>
    </definition>

    <definition id="oval:com.ubuntu.noble:def:9300" class="vulnerability" version="1">
      <metadata>
        <title>CVE-4000-0004 on Ubuntu 24.04 LTS (noble)</title>
        <reference source="CVE" ref_id="CVE-4000-0004" ref_url="https://ubuntu.com/security/CVE-4000-0004" />
        <advisory><severity>Critical</severity></advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" comment="Ubuntu 24.04 LTS (noble) is installed" />
        <criteria operator="OR">
          <criterion test_ref="oval:com.ubuntu.noble:tst:9000" comment="Is kernel 'linux-riscv' running?" />
        </criteria>
      </criteria>
    </definition>
  </definitions>

  <tests>
    <ind-def:family_test id="oval:com.ubuntu.noble:tst:100" version="1" check="at least one" comment="Is the host part of the unix family?">
      <ind-def:object object_ref="oval:com.ubuntu.noble:obj:100" />
    </ind-def:family_test>

    <unix-def:uname_test id="oval:com.ubuntu.noble:tst:9000" version="1" check="at least one" comment="Is kernel 'linux-riscv' running?">
      <unix-def:object object_ref="oval:com.ubuntu.noble:obj:200" />
      <unix-def:state state_ref="oval:com.ubuntu.noble:ste:9000" />
    </unix-def:uname_test>
    <unix-def:uname_test id="oval:com.ubuntu.noble:tst:9100" version="1" check="at least one" comment="Is kernel 'linux' running?">
      <unix-def:object object_ref="oval:com.ubuntu.noble:obj:200" />
      <unix-def:state state_ref="oval:com.ubuntu.noble:ste:9100" />
    </unix-def:uname_test>
  </tests>

  <objects>
    <ind-def:family_object id="oval:com.ubuntu.noble:obj:100" version="1" comment="The singleton family object" />
    <unix-def:uname_object id="oval:com.ubuntu.noble:obj:200" version="1" />
  </objects>

  <states>
    <unix-def:uname_state id="oval:com.ubuntu.noble:ste:9000" version="1">
      <unix-def:os_release operation="pattern match">6.8.0-\d+(-generic)</unix-def:os_release>
    </unix-def:uname_state>
    <unix-def:uname_state id="oval:com.ubuntu.noble:ste:9100" version="1">
      <unix-def:os_release operation="pattern match">6.8.0-\d+(-generic|-generic-64k)</unix-def:os_release>
    </unix-def:uname_state>
  </states>
</oval_definitions>
`

// kernelFilterFeedFixture gives both kernel source packages the same image
// binary name, so the feed's own binary map cannot tell them apart for
// 6.8.0-79-generic — just like linux-hwe-6.14 and linux-riscv-6.14 in the real
// feed. Only the agent's dpkg metadata resolves it.
//
// CVE-4000-0003 is deliberately absent from security_issues.cves.
const kernelFilterFeedFixture = `{
  "format": "1",
  "release": "noble",
  "published_at": "2026-08-27T16:19:49Z",
  "packages": {
    "linux": {
      "source_versions": {
        "6.8.0-79.79": {
          "binary_packages": {
            "linux-image-6.8.0-79-generic": "6.8.0-79.79",
            "linux-modules-6.8.0-79-generic": "6.8.0-79.79"
          },
          "pocket": "updates"
        },
        "6.8.0-90.90": {
          "binary_packages": {
            "linux-image-6.8.0-90-generic": "6.8.0-90.90",
            "linux-modules-6.8.0-90-generic": "6.8.0-90.90"
          },
          "pocket": "updates"
        }
      },
      "cves": {
        "CVE-4000-0001": {"source_fixed_version": null, "status": "not-vulnerable"},
        "CVE-4000-0002": {"source_fixed_version": null, "status": "vulnerable"},
        "CVE-4000-0004": {"source_fixed_version": "6.8.0-84.84", "status": "fixed"}
      }
    },
    "linux-riscv": {
      "source_versions": {
        "6.8.0-60.60": {
          "binary_packages": {
            "linux-image-6.8.0-79-generic": "6.8.0-60.60",
            "linux-modules-6.8.0-79-generic": "6.8.0-60.60"
          },
          "pocket": "updates"
        }
      },
      "cves": {
        "CVE-4000-0001": {"source_fixed_version": null, "status": "vulnerable"},
        "CVE-4000-0002": {"source_fixed_version": null, "status": "not-vulnerable"},
        "CVE-4000-0004": {"source_fixed_version": null, "status": "vulnerable"}
      }
    }
  },
  "security_issues": {
    "cves": {
      "CVE-4000-0001": {
        "description": "Affects the riscv kernel only.",
        "published_at": "2026-02-01T00:00:00Z",
        "notes": [], "cvss_severity": "high", "cvss_score": 7.1,
        "ubuntu_priority": "high", "mitigation": null
      },
      "CVE-4000-0002": {
        "description": "Affects the generic kernel.",
        "published_at": "2026-02-02T00:00:00Z",
        "notes": [], "cvss_severity": "high", "cvss_score": 7.5,
        "ubuntu_priority": "high", "mitigation": null
      },
      "CVE-4000-0004": {
        "description": "Fixed in the generic kernel.",
        "published_at": "2026-02-04T00:00:00Z",
        "notes": [], "cvss_severity": "critical", "cvss_score": 9.1,
        "ubuntu_priority": "critical", "mitigation": null
      }
    },
    "usns": {}
  }
}`

// importKernelFilterFixtures stores the OVAL definitions as the CVE source and
// the feed as the pkg source for Ubuntu 24.04.
func importKernelFilterFixtures(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()

	ovalService := services.NewOVALService(pool)

	cveSource, err := ovalService.CreateSource(ctx, "ubuntu", "24.04", "cve", "noble", "https://example.invalid", "dpkg")
	if err != nil {
		t.Fatalf("create CVE source: %v", err)
	}
	if _, err := oval.NewParser(ovalService).ParseAndStore(ctx, cveSource.ID, []byte(kernelFilterOVALFixture)); err != nil {
		t.Fatalf("parse OVAL fixture: %v", err)
	}

	pkgSource, err := ovalService.CreateSource(ctx, "ubuntu", "24.04", "pkg", "noble", "https://example.invalid", "dpkg")
	if err != nil {
		t.Fatalf("create pkg source: %v", err)
	}
	stats, err := oval.NewPkgParser(services.NewPkgFeedService(pool)).
		ParseAndStore(ctx, pkgSource.ID, bytes.NewReader([]byte(kernelFilterFeedFixture)))
	if err != nil {
		t.Fatalf("parse feed fixture: %v", err)
	}
	if stats.KernelPackages != 2 {
		t.Fatalf("classified %d source packages as kernel, want 2", stats.KernelPackages)
	}
}

func scanWithFeed(t *testing.T, ctx context.Context, pool *pgxpool.Pool, serverID int64) {
	t.Helper()
	if _, err := scanner.NewScanner(pool, nil, services.NewPkgFeedService(pool)).ScanServer(ctx, serverID); err != nil {
		t.Fatalf("scan server: %v", err)
	}
}

// kernelFindings lists the CVEs filed against the synthetic kernel package.
func kernelFindings(t *testing.T, ctx context.Context, pool *pgxpool.Pool, serverID int64) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT cve_id FROM findings
		WHERE server_id = $1 AND package_name = 'kernel' AND resolved_at IS NULL
		ORDER BY cve_id
	`, serverID)
	if err != nil {
		t.Fatalf("query kernel findings: %v", err)
	}
	defer rows.Close()

	var cves []string
	for rows.Next() {
		var cve string
		if err := rows.Scan(&cve); err != nil {
			t.Fatalf("scan: %v", err)
		}
		cves = append(cves, cve)
	}
	return cves
}

func assertKernelFindings(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("kernel findings mismatch\n got: %v\nwant: %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("kernel findings mismatch\n got: %v\nwant: %v", got, want)
		}
	}
}

// TestKernelFilterSuppressesForeignFlavour is the reported case: an amd64 host
// on the 24.04 GA kernel must not inherit the riscv kernel's CVEs.
func TestKernelFilterSuppressesForeignFlavour(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importKernelFilterFixtures(t, ctx, pool)

	serverID := createServerWithSources(t, ctx, pool, "6.8.0-79-generic", map[string][2]string{
		"linux-modules-6.8.0-79-generic": {"6.8.0-79.79", "linux"},
	})
	scanWithFeed(t, ctx, pool, serverID)

	assertKernelFindings(t, kernelFindings(t, ctx, pool, serverID), []string{
		// CVE-4000-0001 is gone: only the riscv criterion matched, and the feed
		// says the linux kernel is not affected.
		"CVE-4000-0002", // the genuine linux criterion
		"CVE-4000-0003", // the feed does not track it -> fail open
		"CVE-4000-0004", // fixed in 6.8.0-84.84, the host runs 6.8.0-79
	})
}

// TestKernelFilterKeepsRiscvHost is the mirror image: on riscv64 the very same
// release string is genuinely affected, and the generic kernel's CVE is not.
func TestKernelFilterKeepsRiscvHost(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importKernelFilterFixtures(t, ctx, pool)

	serverID := createServerWithSources(t, ctx, pool, "6.8.0-79-generic", map[string][2]string{
		"linux-modules-6.8.0-79-generic": {"6.8.0-60.60", "linux-riscv"},
	})
	scanWithFeed(t, ctx, pool, serverID)

	assertKernelFindings(t, kernelFindings(t, ctx, pool, serverID), []string{
		"CVE-4000-0001", // riscv really is affected
		// CVE-4000-0002 is gone: the feed says riscv is not affected
		"CVE-4000-0003",
		"CVE-4000-0004",
	})
}

// TestKernelFilterVersionAware covers the "fixed" branch: once the running
// kernel is past the fixed version, the finding goes.
func TestKernelFilterVersionAware(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importKernelFilterFixtures(t, ctx, pool)

	serverID := createServerWithSources(t, ctx, pool, "6.8.0-90-generic", map[string][2]string{
		"linux-modules-6.8.0-90-generic": {"6.8.0-90.90", "linux"},
	})
	scanWithFeed(t, ctx, pool, serverID)

	assertKernelFindings(t, kernelFindings(t, ctx, pool, serverID), []string{
		"CVE-4000-0002",
		"CVE-4000-0003",
		// CVE-4000-0004 is gone: fixed in 6.8.0-84.84, the host runs 6.8.0-90
	})
}

// TestKernelFilterIgnoresSignedImageSource guards the most dangerous failure
// mode. The signed kernel image belongs to the source package "linux-signed",
// which the feed does not contain at all; accepting it would yield an empty
// verdict set and suppress *every* kernel finding.
func TestKernelFilterIgnoresSignedImageSource(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importKernelFilterFixtures(t, ctx, pool)

	serverID := createServerWithSources(t, ctx, pool, "6.8.0-79-generic", map[string][2]string{
		// Only the signed image, exactly as dpkg reports it on a real host.
		"linux-image-6.8.0-79-generic": {"6.8.0-79.79", "linux-signed"},
	})
	scanWithFeed(t, ctx, pool, serverID)

	// linux-signed is rejected, and the feed's binary map cannot tell linux from
	// linux-riscv for this release, so nothing is filtered.
	assertKernelFindings(t, kernelFindings(t, ctx, pool, serverID), []string{
		"CVE-4000-0001", "CVE-4000-0002", "CVE-4000-0003", "CVE-4000-0004",
	})
}

// TestKernelFilterFailsOpenWithoutAgentSource covers hosts whose agent does not
// report source packages and whose release string is ambiguous in the feed.
func TestKernelFilterFailsOpenWithoutAgentSource(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importKernelFilterFixtures(t, ctx, pool)

	serverID := createServerWithSources(t, ctx, pool, "6.8.0-79-generic", map[string][2]string{
		"linux-modules-6.8.0-79-generic": {"6.8.0-79.79", ""},
	})
	scanWithFeed(t, ctx, pool, serverID)

	assertKernelFindings(t, kernelFindings(t, ctx, pool, serverID), []string{
		"CVE-4000-0001", "CVE-4000-0002", "CVE-4000-0003", "CVE-4000-0004",
	})
}

// TestKernelFilterResolvesUnambiguousReleaseFromFeed covers the fallback: when
// the release maps to exactly one kernel source package, the feed alone is
// enough even without any agent metadata.
func TestKernelFilterResolvesUnambiguousReleaseFromFeed(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importKernelFilterFixtures(t, ctx, pool)

	// 6.8.0-90-generic is built by "linux" only — linux-riscv stops at 6.8.0-79
	// in this fixture, mirroring the real feed's diverging ABI ranges.
	serverID := createServerWithSources(t, ctx, pool, "6.8.0-90-generic", map[string][2]string{
		"linux-modules-6.8.0-90-generic": {"6.8.0-90.90", ""},
	})
	scanWithFeed(t, ctx, pool, serverID)

	assertKernelFindings(t, kernelFindings(t, ctx, pool, serverID), []string{
		"CVE-4000-0002",
		"CVE-4000-0003",
	})
}

// TestKernelFilterInertWithoutFeed checks the two ways the cross-check switches
// itself off.
func TestKernelFilterInertWithoutFeed(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importKernelFilterFixtures(t, ctx, pool)

	serverID := createServerWithSources(t, ctx, pool, "6.8.0-79-generic", map[string][2]string{
		"linux-modules-6.8.0-79-generic": {"6.8.0-79.79", "linux"},
	})

	all := []string{"CVE-4000-0001", "CVE-4000-0002", "CVE-4000-0003", "CVE-4000-0004"}

	// No feed service wired into the scanner.
	if _, err := scanner.NewScanner(pool, nil, nil).ScanServer(ctx, serverID); err != nil {
		t.Fatalf("scan without the feed service: %v", err)
	}
	assertKernelFindings(t, kernelFindings(t, ctx, pool, serverID), all)

	// Feed source disabled.
	if _, err := pool.Exec(ctx, `UPDATE oval_sources SET is_enabled = false WHERE source_type = 'pkg'`); err != nil {
		t.Fatalf("disable feed source: %v", err)
	}
	scanWithFeed(t, ctx, pool, serverID)
	assertKernelFindings(t, kernelFindings(t, ctx, pool, serverID), all)
}

// TestKernelFilterResolvesStaleFinding checks that a finding the cross-check
// starts rejecting is marked resolved rather than left behind as active.
func TestKernelFilterResolvesStaleFinding(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importKernelFilterFixtures(t, ctx, pool)

	// First scan as a riscv host, where CVE-4000-0001 genuinely applies.
	serverID := createServerWithSources(t, ctx, pool, "6.8.0-79-generic", map[string][2]string{
		"linux-modules-6.8.0-79-generic": {"6.8.0-60.60", "linux-riscv"},
	})
	scanWithFeed(t, ctx, pool, serverID)
	if got := kernelFindings(t, ctx, pool, serverID); len(got) != 3 || got[0] != "CVE-4000-0001" {
		t.Fatalf("expected CVE-4000-0001 to be active after the first scan, got %v", got)
	}

	// Correct the reported source package to the generic kernel and rescan.
	if _, err := pool.Exec(ctx, `
		UPDATE server_packages SET source_package = 'linux'
		WHERE server_id = $1 AND name = 'linux-modules-6.8.0-79-generic'
	`, serverID); err != nil {
		t.Fatalf("update source package: %v", err)
	}
	scanWithFeed(t, ctx, pool, serverID)

	var resolved *string
	if err := pool.QueryRow(ctx, `
		SELECT resolved_at::text FROM findings
		WHERE server_id = $1 AND cve_id = 'CVE-4000-0001' AND package_name = 'kernel'
	`, serverID).Scan(&resolved); err != nil {
		t.Fatalf("query the suppressed finding: %v", err)
	}
	if resolved == nil {
		t.Error("the suppressed finding is still active; it should be marked resolved")
	}
}
