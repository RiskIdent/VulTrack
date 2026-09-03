package scanner_test

// Integration coverage for the import -> link -> evaluate pipeline against an
// OVAL document that reproduces the shapes Canonical actually publishes: tests
// sharing an object, tests sharing a state, kernel-only definitions gated on a
// single flavour, existence-only package tests next to kernel tests, and objects
// whose package names come from a constant_variable.
//
// Requires a throwaway PostgreSQL:
//
//	docker run -d --rm -e POSTGRES_PASSWORD=test -e POSTGRES_USER=test \
//	    -e POSTGRES_DB=test -p 55432:5432 postgres:16-alpine
//	VULTRACK_TEST_DATABASE_URL='postgres://test:test@127.0.0.1:55432/test' \
//	    go test ./internal/scanner/ -run TestOVALPipeline
//
// The schema of that database is dropped and recreated, so never point it at a
// database holding real data.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/database"
	"github.com/vultrack/vultrack/internal/oval"
	"github.com/vultrack/vultrack/internal/scanner"
	"github.com/vultrack/vultrack/internal/services"
)

// ovalFixture mirrors com.ubuntu.noble. The numeric parts of the tst/obj/ste IDs
// deliberately disagree in places: that is what the old "same numeric suffix"
// heuristic got wrong.
//
//	tst:2000 -> obj:2000 (libnvidia-cfg1-470),        ste:2000
//	tst:2010 -> obj:2010 (libnvidia-cfg1-470-server), ste:2000  <- shared state
//	tst:3000 -> obj:2000 (libnvidia-cfg1-470),        ste:3000  <- shared object
//	tst:5000 -> obj:5010 (amd64-microcode),           no state  <- shifted object, existence only
const ovalFixture = `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
                  xmlns:ind-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"
                  xmlns:unix-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"
                  xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <generator>
    <product_name>Canonical OVAL Generator</product_name>
    <schema_version>5.11.1</schema_version>
  </generator>

  <definitions>
    <definition id="oval:com.ubuntu.noble:def:100" class="inventory" version="1">
      <metadata><title>Check that Ubuntu 24.04 LTS (noble) is installed.</title></metadata>
      <criteria>
        <criterion test_ref="oval:com.ubuntu.noble:tst:100" comment="The host is part of the unix family." />
        <criterion test_ref="oval:com.ubuntu.noble:tst:101" comment="The host is running Ubuntu 24.04 LTS (noble)." />
      </criteria>
    </definition>

    <definition id="oval:com.ubuntu.noble:def:2000" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2000-0001 on Ubuntu 24.04 LTS (noble)</title>
        <reference source="CVE" ref_id="CVE-2000-0001" ref_url="https://ubuntu.com/security/CVE-2000-0001" />
        <advisory><severity>Medium</severity></advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" comment="Ubuntu 24.04 LTS (noble) is installed" />
        <criteria operator="OR">
          <criterion test_ref="oval:com.ubuntu.noble:tst:2000" comment="nvidia-graphics-drivers-470 source package in noble, is affected and has been fixed (note: '470.223.02-0ubuntu1')." />
          <criterion test_ref="oval:com.ubuntu.noble:tst:2010" comment="nvidia-graphics-drivers-470-server source package in noble, is affected and has been fixed (note: '470.223.02-0ubuntu1')." />
        </criteria>
      </criteria>
    </definition>

    <definition id="oval:com.ubuntu.noble:def:3000" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2000-0002 on Ubuntu 24.04 LTS (noble)</title>
        <reference source="CVE" ref_id="CVE-2000-0002" ref_url="https://ubuntu.com/security/CVE-2000-0002" />
        <advisory><severity>High</severity></advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" comment="Ubuntu 24.04 LTS (noble) is installed" />
        <criteria operator="OR">
          <criterion test_ref="oval:com.ubuntu.noble:tst:3000" comment="nvidia-graphics-drivers-470 source package in noble was vulnerable but has been fixed (note: '470.300.00-0ubuntu1')." />
        </criteria>
      </criteria>
    </definition>

    <definition id="oval:com.ubuntu.noble:def:4000" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2000-0003 on Ubuntu 24.04 LTS (noble)</title>
        <reference source="CVE" ref_id="CVE-2000-0003" ref_url="https://ubuntu.com/security/CVE-2000-0003" />
        <advisory><severity>Low</severity></advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" comment="Ubuntu 24.04 LTS (noble) is installed" />
        <criteria operator="OR">
          <criterion test_ref="oval:com.ubuntu.noble:tst:4000" comment="Is kernel 'linux' running?" />
        </criteria>
      </criteria>
    </definition>

    <definition id="oval:com.ubuntu.noble:def:4100" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2000-0004 on Ubuntu 24.04 LTS (noble)</title>
        <reference source="CVE" ref_id="CVE-2000-0004" ref_url="https://ubuntu.com/security/CVE-2000-0004" />
        <advisory><severity>Low</severity></advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" comment="Ubuntu 24.04 LTS (noble) is installed" />
        <criteria operator="OR">
          <criterion test_ref="oval:com.ubuntu.noble:tst:4100" comment="Is kernel 'linux-hwe-7.0' running?" />
        </criteria>
      </criteria>
    </definition>

    <definition id="oval:com.ubuntu.noble:def:5000" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2000-0005 on Ubuntu 24.04 LTS (noble)</title>
        <reference source="CVE" ref_id="CVE-2000-0005" ref_url="https://ubuntu.com/security/CVE-2000-0005" />
        <advisory><severity>Low</severity></advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" comment="Ubuntu 24.04 LTS (noble) is installed" />
        <criteria operator="OR">
          <criterion test_ref="oval:com.ubuntu.noble:tst:5000" comment="amd64-microcode source package in noble, might be affected and may need fixing." />
          <criterion test_ref="oval:com.ubuntu.noble:tst:4000" comment="Is kernel 'linux' running?" />
        </criteria>
      </criteria>
    </definition>

    <definition id="oval:com.ubuntu.noble:def:6000" class="patch" version="1">
      <metadata>
        <title>USN-9999-1 -- Linux kernel vulnerabilities</title>
        <reference source="CVE" ref_id="CVE-2000-0006" ref_url="https://ubuntu.com/security/CVE-2000-0006" />
        <advisory><severity>High</severity></advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" comment="Ubuntu 24.04 LTS (noble) is installed" />
        <criteria operator="AND">
          <criterion test_ref="oval:com.ubuntu.noble:tst:4000" comment="Is kernel 'linux' running?" />
          <criterion test_ref="oval:com.ubuntu.noble:tst:6000" comment="'linux' kernel in noble was vulnerable but has been fixed (note: '6.8.0-84.84')." />
        </criteria>
      </criteria>
    </definition>

    <definition id="oval:com.ubuntu.noble:def:7000" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2000-0007 on Ubuntu 24.04 LTS (noble)</title>
        <reference source="CVE" ref_id="CVE-2000-0007" ref_url="https://ubuntu.com/security/CVE-2000-0007" />
        <advisory><severity>Medium</severity></advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" comment="Ubuntu 24.04 LTS (noble) is installed" />
        <criteria operator="AND">
          <criterion test_ref="oval:com.ubuntu.noble:tst:7000" comment="installed-pkg package in noble, is affected and needs fixing." />
          <criterion test_ref="oval:com.ubuntu.noble:tst:7010" comment="missing-pkg package in noble, is affected and needs fixing." />
        </criteria>
      </criteria>
    </definition>

    <definition id="oval:com.ubuntu.noble:def:8000" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2000-0008 on Ubuntu 24.04 LTS (noble)</title>
        <reference source="CVE" ref_id="CVE-2000-0008" ref_url="https://ubuntu.com/security/CVE-2000-0008" />
        <advisory><severity>Critical</severity></advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" comment="Ubuntu 24.04 LTS (noble) is installed" />
        <criteria operator="OR">
          <criterion test_ref="oval:com.ubuntu.noble:tst:8000" comment="foo source package in noble was vulnerable but has been fixed (note: '2.0-1')." />
        </criteria>
      </criteria>
    </definition>
  </definitions>

  <tests>
    <ind-def:family_test id="oval:com.ubuntu.noble:tst:100" version="1" check="at least one" comment="Is the host part of the unix family?">
      <ind-def:object object_ref="oval:com.ubuntu.noble:obj:100" />
      <ind-def:state state_ref="oval:com.ubuntu.noble:ste:100" />
    </ind-def:family_test>
    <ind-def:textfilecontent54_test id="oval:com.ubuntu.noble:tst:101" version="1" check="at least one" comment="Is the host running Ubuntu noble?">
      <ind-def:object object_ref="oval:com.ubuntu.noble:obj:101" />
      <ind-def:state state_ref="oval:com.ubuntu.noble:ste:101" />
    </ind-def:textfilecontent54_test>

    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:2000" version="1" check="at least one" comment="Does the 'nvidia-graphics-drivers-470' package exist?">
      <linux-def:object object_ref="oval:com.ubuntu.noble:obj:2000" />
      <linux-def:state state_ref="oval:com.ubuntu.noble:ste:2000" />
    </linux-def:dpkginfo_test>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:2010" version="1" check="at least one" comment="Does the 'nvidia-graphics-drivers-470-server' package exist?">
      <linux-def:object object_ref="oval:com.ubuntu.noble:obj:2010" />
      <linux-def:state state_ref="oval:com.ubuntu.noble:ste:2000" />
    </linux-def:dpkginfo_test>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:3000" version="1" check="at least one" comment="Does the 'nvidia-graphics-drivers-470' package exist?">
      <linux-def:object object_ref="oval:com.ubuntu.noble:obj:2000" />
      <linux-def:state state_ref="oval:com.ubuntu.noble:ste:3000" />
    </linux-def:dpkginfo_test>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:5000" version="1" check="at least one" comment="Does the 'amd64-microcode' package exist?">
      <linux-def:object object_ref="oval:com.ubuntu.noble:obj:5010" />
    </linux-def:dpkginfo_test>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:7000" version="1" check="at least one" comment="Does the 'installed-pkg' package exist?">
      <linux-def:object object_ref="oval:com.ubuntu.noble:obj:7000" />
    </linux-def:dpkginfo_test>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:7010" version="1" check="at least one" comment="Does the 'missing-pkg' package exist?">
      <linux-def:object object_ref="oval:com.ubuntu.noble:obj:7010" />
    </linux-def:dpkginfo_test>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:8000" version="1" check="at least one" comment="Does the 'foo' package exist?">
      <linux-def:object object_ref="oval:com.ubuntu.noble:obj:8000" />
      <linux-def:state state_ref="oval:com.ubuntu.noble:ste:8000" />
    </linux-def:dpkginfo_test>

    <unix-def:uname_test id="oval:com.ubuntu.noble:tst:4000" version="1" check="at least one" comment="Is kernel 'linux' running?">
      <unix-def:object object_ref="oval:com.ubuntu.noble:obj:200" />
      <unix-def:state state_ref="oval:com.ubuntu.noble:ste:4000" />
    </unix-def:uname_test>
    <unix-def:uname_test id="oval:com.ubuntu.noble:tst:4100" version="1" check="at least one" comment="Is kernel 'linux-hwe-7.0' running?">
      <unix-def:object object_ref="oval:com.ubuntu.noble:obj:200" />
      <unix-def:state state_ref="oval:com.ubuntu.noble:ste:4100" />
    </unix-def:uname_test>
    <ind-def:variable_test id="oval:com.ubuntu.noble:tst:6000" version="1" check="at least one" comment="'linux' kernel version comparison">
      <ind-def:object object_ref="oval:com.ubuntu.noble:obj:210" />
      <ind-def:state state_ref="oval:com.ubuntu.noble:ste:6000" />
    </ind-def:variable_test>
  </tests>

  <objects>
    <ind-def:family_object id="oval:com.ubuntu.noble:obj:100" version="1" comment="The singleton family object" />
    <ind-def:textfilecontent54_object id="oval:com.ubuntu.noble:obj:101" version="1">
      <ind-def:filepath datatype="string">/etc/lsb-release</ind-def:filepath>
    </ind-def:textfilecontent54_object>
    <unix-def:uname_object id="oval:com.ubuntu.noble:obj:200" version="1" />
    <ind-def:variable_object id="oval:com.ubuntu.noble:obj:210" version="1">
      <ind-def:var_ref>oval:com.ubuntu.noble:var:200</ind-def:var_ref>
    </ind-def:variable_object>

    <linux-def:dpkginfo_object id="oval:com.ubuntu.noble:obj:2000" version="1">
      <linux-def:name>libnvidia-cfg1-470</linux-def:name>
    </linux-def:dpkginfo_object>
    <linux-def:dpkginfo_object id="oval:com.ubuntu.noble:obj:2010" version="1">
      <linux-def:name>libnvidia-cfg1-470-server</linux-def:name>
    </linux-def:dpkginfo_object>
    <linux-def:dpkginfo_object id="oval:com.ubuntu.noble:obj:5010" version="1">
      <linux-def:name>amd64-microcode</linux-def:name>
    </linux-def:dpkginfo_object>
    <linux-def:dpkginfo_object id="oval:com.ubuntu.noble:obj:7000" version="1">
      <linux-def:name>installed-pkg</linux-def:name>
    </linux-def:dpkginfo_object>
    <linux-def:dpkginfo_object id="oval:com.ubuntu.noble:obj:7010" version="1">
      <linux-def:name>missing-pkg</linux-def:name>
    </linux-def:dpkginfo_object>
    <linux-def:dpkginfo_object id="oval:com.ubuntu.noble:obj:8000" version="1" comment="The 'foo' package binaries">
      <linux-def:name var_ref="oval:com.ubuntu.noble:var:8000" var_check="at least one" />
    </linux-def:dpkginfo_object>
  </objects>

  <states>
    <linux-def:dpkginfo_state id="oval:com.ubuntu.noble:ste:2000" version="1">
      <linux-def:evr datatype="debian_evr_string" operation="less than">470.223.02-0ubuntu1</linux-def:evr>
    </linux-def:dpkginfo_state>
    <linux-def:dpkginfo_state id="oval:com.ubuntu.noble:ste:3000" version="1">
      <linux-def:evr datatype="debian_evr_string" operation="less than">470.300.00-0ubuntu1</linux-def:evr>
    </linux-def:dpkginfo_state>
    <linux-def:dpkginfo_state id="oval:com.ubuntu.noble:ste:8000" version="1">
      <linux-def:evr datatype="debian_evr_string" operation="less than">2.0-1</linux-def:evr>
    </linux-def:dpkginfo_state>

    <unix-def:uname_state id="oval:com.ubuntu.noble:ste:4000" version="1">
      <unix-def:os_release operation="pattern match">6.8.0-\d+(-generic|-generic-64k)</unix-def:os_release>
    </unix-def:uname_state>
    <unix-def:uname_state id="oval:com.ubuntu.noble:ste:4100" version="1">
      <unix-def:os_release operation="pattern match">7.0.0-\d+(-generic|-generic-64k)</unix-def:os_release>
    </unix-def:uname_state>
    <ind-def:variable_state id="oval:com.ubuntu.noble:ste:6000" version="1" comment="'linux' kernel version">
      <ind-def:value datatype="debian_evr_string" operation="less than">6.8.0-84.84</ind-def:value>
    </ind-def:variable_state>
  </states>

  <variables>
    <local_variable id="oval:com.ubuntu.noble:var:200" version="1" datatype="debian_evr_string" comment="kernel version in evr format">
      <concat>
        <literal_component>0:</literal_component>
        <regex_capture pattern="^([\d|\.]+-\d+)[-|\w]+$">
          <object_component object_ref="oval:com.ubuntu.noble:obj:200" item_field="os_release" />
        </regex_capture>
      </concat>
    </local_variable>
    <constant_variable id="oval:com.ubuntu.noble:var:8000" version="1" datatype="string" comment="The 'foo' package binaries">
      <value>libfoo1</value>
      <value>libfoo-dev</value>
      <value>foo-tools</value>
    </constant_variable>
  </variables>
</oval_definitions>
`

type findingRow struct {
	CVEID    string
	Package  string
	FixState string
	FixedIn  string
}

func (f findingRow) String() string {
	return fmt.Sprintf("%s/%s(%s,fixed_in=%q)", f.CVEID, f.Package, f.FixState, f.FixedIn)
}

func setupPipeline(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()

	dsn := os.Getenv("VULTRACK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("VULTRACK_TEST_DATABASE_URL not set; skipping OVAL pipeline integration test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)

	// Start from an empty schema so repeated runs are independent.
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset test schema: %v", err)
	}
	if err := database.Migrate(pool); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	return pool, ctx
}

// importFixture stores the fixture as the CVE OVAL source for Ubuntu 24.04 and
// returns the source ID.
func importFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int64 {
	t.Helper()

	ovalService := services.NewOVALService(pool)
	source, err := ovalService.CreateSource(ctx, "ubuntu", "24.04", "cve", "noble",
		"https://example.invalid/com.ubuntu.noble.cve.oval.xml.bz2", "dpkg")
	if err != nil {
		t.Fatalf("create OVAL source: %v", err)
	}

	stats, err := oval.NewParser(ovalService).ParseAndStore(ctx, source.ID, []byte(ovalFixture))
	if err != nil {
		t.Fatalf("parse OVAL fixture: %v", err)
	}
	if stats.TotalDefinitions != 9 {
		t.Fatalf("parsed %d definitions, want 9", stats.TotalDefinitions)
	}
	// 7 dpkginfo + 2 uname + 1 variable; family_test and textfilecontent54_test
	// are not evaluatable and are not stored.
	if stats.TotalTests != 10 {
		t.Fatalf("parsed %d tests, want 10", stats.TotalTests)
	}
	return source.ID
}

func createServer(t *testing.T, ctx context.Context, pool *pgxpool.Pool, kernel string, packages map[string]string) int64 {
	t.Helper()

	var serverID int64
	err := pool.QueryRow(ctx, `
		INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager)
		VALUES ('test-noble', 'ubuntu', '24.04', 'noble', $1, 'amd64', 'dpkg')
		RETURNING id
	`, kernel).Scan(&serverID)
	if err != nil {
		t.Fatalf("insert server: %v", err)
	}

	for name, version := range packages {
		_, err := pool.Exec(ctx, `
			INSERT INTO server_packages (server_id, name, version, arch, first_seen_at, last_seen_at)
			VALUES ($1, $2, $3, 'amd64', NOW(), NOW())
		`, serverID, name, version)
		if err != nil {
			t.Fatalf("insert package %s: %v", name, err)
		}
	}
	return serverID
}

func activeFindings(t *testing.T, ctx context.Context, pool *pgxpool.Pool, serverID int64) []findingRow {
	t.Helper()

	rows, err := pool.Query(ctx, `
		SELECT cve_id, package_name, COALESCE(fix_state, ''), COALESCE(fixed_in, '')
		FROM findings
		WHERE server_id = $1 AND resolved_at IS NULL
		ORDER BY cve_id, package_name
	`, serverID)
	if err != nil {
		t.Fatalf("query findings: %v", err)
	}
	defer rows.Close()

	var findings []findingRow
	for rows.Next() {
		var f findingRow
		if err := rows.Scan(&f.CVEID, &f.Package, &f.FixState, &f.FixedIn); err != nil {
			t.Fatalf("scan finding: %v", err)
		}
		findings = append(findings, f)
	}
	return findings
}

func assertFindings(t *testing.T, got []findingRow, want []findingRow) {
	t.Helper()

	format := func(rows []findingRow) []string {
		out := make([]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, r.String())
		}
		sort.Strings(out)
		return out
	}

	gotStrings, wantStrings := format(got), format(want)
	if len(gotStrings) != len(wantStrings) {
		t.Fatalf("findings mismatch\n got: %v\nwant: %v", gotStrings, wantStrings)
	}
	for i := range gotStrings {
		if gotStrings[i] != wantStrings[i] {
			t.Fatalf("findings mismatch\n got: %v\nwant: %v", gotStrings, wantStrings)
		}
	}
}

func TestOVALPipelineFindings(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importFixture(t, ctx, pool)

	serverID := createServer(t, ctx, pool, "6.8.0-79-generic", map[string]string{
		// Both nvidia packages are already at the version ste:2000 asks for. The
		// version comparison must survive the fact that tst:2010 shares that state
		// with tst:2000, otherwise the test degrades into "installed = affected".
		"libnvidia-cfg1-470":        "470.223.02-0ubuntu1",
		"libnvidia-cfg1-470-server": "470.223.02-0ubuntu1",
		// Reached only through tst:5000, whose object ID does not match the test ID.
		"amd64-microcode": "3.20240710.3ubuntu1",
		// One half of an AND; the other package is not installed.
		"installed-pkg": "1.0-1",
		// From the constant_variable expansion: one outdated, one current,
		// libfoo-dev not installed at all.
		"libfoo1":   "1.9-1",
		"foo-tools": "2.0-1",
	})

	result, err := scanner.NewScanner(pool, nil, nil).ScanServer(ctx, serverID)
	if err != nil {
		t.Fatalf("scan server: %v", err)
	}
	if result.TotalChecks == 0 {
		t.Fatal("scan evaluated no definitions")
	}

	assertFindings(t, activeFindings(t, ctx, pool, serverID), []findingRow{
		// CVE-2000-0001: both packages patched -> nothing.
		// CVE-2000-0002: tst:3000 reuses obj:2000 and demands 470.300.00.
		{CVEID: "CVE-2000-0002", Package: "libnvidia-cfg1-470", FixState: "fix_available", FixedIn: "470.300.00-0ubuntu1"},
		// CVE-2000-0003: the running 6.8.0 kernel matches "Is kernel 'linux' running?".
		{CVEID: "CVE-2000-0003", Package: "kernel", FixState: "affected"},
		// CVE-2000-0004: gated on the 26.04-era linux-hwe-7.0 kernel -> nothing.
		// CVE-2000-0005: a microcode issue must be filed against the package.
		{CVEID: "CVE-2000-0005", Package: "amd64-microcode", FixState: "affected"},
		// CVE-2000-0006: kernel flavour matches AND 0:6.8.0-79 < 6.8.0-84.84.
		{CVEID: "CVE-2000-0006", Package: "kernel", FixState: "affected"},
		// CVE-2000-0007: AND over two packages, one not installed -> nothing.
		// CVE-2000-0008: only the outdated binary of the expanded object.
		{CVEID: "CVE-2000-0008", Package: "libfoo1", FixState: "fix_available", FixedIn: "2.0-1"},
	})
}

// TestOVALPipelinePatchedKernel checks that a kernel past the fixed version stops
// being reported, and that the stale finding is resolved on the next scan.
func TestOVALPipelinePatchedKernel(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importFixture(t, ctx, pool)

	serverID := createServer(t, ctx, pool, "6.8.0-79-generic", map[string]string{
		"installed-pkg": "1.0-1",
	})
	s := scanner.NewScanner(pool, nil, nil)

	if _, err := s.ScanServer(ctx, serverID); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	assertFindings(t, activeFindings(t, ctx, pool, serverID), []findingRow{
		{CVEID: "CVE-2000-0003", Package: "kernel", FixState: "affected"},
		{CVEID: "CVE-2000-0005", Package: "kernel", FixState: "affected"},
		{CVEID: "CVE-2000-0006", Package: "kernel", FixState: "affected"},
	})

	// Upgrade past ste:6000 (6.8.0-84.84). CVE-2000-0006 must go away; the two
	// "no fix available yet" kernel definitions still apply to the flavour.
	if _, err := pool.Exec(ctx, `UPDATE servers SET kernel = '6.8.0-90-generic' WHERE id = $1`, serverID); err != nil {
		t.Fatalf("update kernel: %v", err)
	}
	if _, err := s.ScanServer(ctx, serverID); err != nil {
		t.Fatalf("second scan: %v", err)
	}
	assertFindings(t, activeFindings(t, ctx, pool, serverID), []findingRow{
		{CVEID: "CVE-2000-0003", Package: "kernel", FixState: "affected"},
		{CVEID: "CVE-2000-0005", Package: "kernel", FixState: "affected"},
	})
}

// TestOVALPipelineForeignKernelFlavour checks that a definition covering only
// other kernel flavours does not produce findings.
func TestOVALPipelineForeignKernelFlavour(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importFixture(t, ctx, pool)

	serverID := createServer(t, ctx, pool, "6.8.0-1029-aws", map[string]string{
		"installed-pkg": "1.0-1",
	})

	if _, err := scanner.NewScanner(pool, nil, nil).ScanServer(ctx, serverID); err != nil {
		t.Fatalf("scan server: %v", err)
	}
	// Neither the generic nor the hwe-7.0 pattern matches an -aws kernel, and the
	// microcode package is not installed.
	assertFindings(t, activeFindings(t, ctx, pool, serverID), nil)
}

// TestOVALDefinitionDetails covers the OVAL browser: affected packages and the
// per-test version comparison come from the same stored references as the scan.
func TestOVALDefinitionDetails(t *testing.T) {
	pool, ctx := setupPipeline(t)
	importFixture(t, ctx, pool)

	ovalService := services.NewOVALService(pool)

	byCVE := func(cveID string) *services.OVALDefinitionWithSource {
		t.Helper()
		defs, total, err := ovalService.GetDefinitions(ctx, services.OVALDefinitionFilter{
			CVEID: &cveID,
			Limit: 10,
		})
		if err != nil {
			t.Fatalf("get definitions for %s: %v", cveID, err)
		}
		if total != 1 || len(defs) != 1 {
			t.Fatalf("expected exactly one definition for %s, got %d", cveID, total)
		}
		detail, err := ovalService.GetDefinitionByID(ctx, defs[0].ID)
		if err != nil {
			t.Fatalf("get definition detail for %s: %v", cveID, err)
		}
		return detail
	}

	// Shared state: both tests must still show their version comparison.
	def := byCVE("CVE-2000-0001")
	assertStringSet(t, "affected packages", def.AffectedPackages,
		[]string{"libnvidia-cfg1-470", "libnvidia-cfg1-470-server"})
	for _, test := range def.Tests {
		if test.EVROperation != "less than" || test.EVRValue != "470.223.02-0ubuntu1" {
			t.Errorf("test %s lost its version comparison: %q %q",
				test.OvalID, test.EVROperation, test.EVRValue)
		}
	}

	// Shared object: the reused object's package must be resolved.
	assertStringSet(t, "affected packages", byCVE("CVE-2000-0002").AffectedPackages,
		[]string{"libnvidia-cfg1-470"})

	// Kernel-only definition.
	assertStringSet(t, "affected packages", byCVE("CVE-2000-0003").AffectedPackages,
		[]string{"Kernel"})

	// Existence-only test on a shifted object ID.
	assertStringSet(t, "affected packages", byCVE("CVE-2000-0005").AffectedPackages,
		[]string{"amd64-microcode"})

	// constant_variable expansion.
	assertStringSet(t, "affected packages", byCVE("CVE-2000-0008").AffectedPackages,
		[]string{"foo-tools", "libfoo-dev", "libfoo1"})

	// The package filter must only match definitions that really test the package,
	// not every definition of the source.
	pkg := "libnvidia-cfg1-470-server"
	defs, total, err := ovalService.GetDefinitions(ctx, services.OVALDefinitionFilter{Package: &pkg, Limit: 50})
	if err != nil {
		t.Fatalf("filter definitions by package: %v", err)
	}
	if total != 1 || len(defs) != 1 || defs[0].CVEIDs[0] != "CVE-2000-0001" {
		got := make([]string, 0, len(defs))
		for _, d := range defs {
			got = append(got, d.CVEIDs...)
		}
		t.Fatalf("package filter %q matched %d definitions (%v), want only CVE-2000-0001", pkg, total, got)
	}
}

func assertStringSet(t *testing.T, what string, got, want []string) {
	t.Helper()

	gotSorted := append([]string(nil), got...)
	wantSorted := append([]string(nil), want...)
	sort.Strings(gotSorted)
	sort.Strings(wantSorted)

	if len(gotSorted) != len(wantSorted) {
		t.Fatalf("%s: got %v, want %v", what, gotSorted, wantSorted)
	}
	for i := range gotSorted {
		if gotSorted[i] != wantSorted[i] {
			t.Fatalf("%s: got %v, want %v", what, gotSorted, wantSorted)
		}
	}
}
