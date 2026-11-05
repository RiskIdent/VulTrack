package services_test

// The "Automated assessments" PDF section appears only when requested and
// covers decisions, dismissed CVEs and per-server human decisions.
//
// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/vultrack/vultrack/internal/autoassess"
	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

func TestReportAutoAssessmentSection(t *testing.T) {
	pool, ctx := testdb.Setup(t, "report_auto_assessment_tests")
	settings := services.NewSettingsService(pool)

	var ids []int64
	for _, name := range []string{"web-01", "db-01"} {
		var id int64
		if err := pool.QueryRow(ctx, `
			INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager)
			VALUES ($1, 'ubuntu', '24.04', 'noble', '6.8.0', 'amd64', 'dpkg') RETURNING id`, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		for _, f := range [][2]string{{"CVE-2026-1001", "linux-libc-dev"}, {"CVE-2026-1002", "libfoo1"}, {"CVE-2026-1003", "openssl-doc"}} {
			if _, err := pool.Exec(ctx, `
				INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state, severity, source_type, summary, first_seen_at, last_seen_at)
				VALUES ($1, $2, $3, '1.0', 'affected', 'high', 'usn', 'summary', NOW() - interval '2 days', NOW())`, id, f[0], f[1]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := settings.SetMultiple(ctx, map[string]string{"auto_assessment_mode": "active", "auto_assessment_rule_modes": `{"R-HDR":"active"}`}); err != nil {
		t.Fatal(err)
	}
	eval := autoassess.New(pool, settings)
	for _, id := range ids {
		if _, err := eval.EvaluateServer(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := services.NewAutoAssessmentService(pool).SetOverride(ctx, ids[1], "CVE-2026-1003", "relevant", "docs are served by the web server", "alice"); err != nil {
		t.Fatal(err)
	}

	reports := services.NewReportService(pool)
	req := services.ReportRequest{
		StartDate: time.Now().AddDate(0, -1, 0), EndDate: time.Now().Add(time.Hour),
		IncludeTopCVEs: true, IncludeAutoAssessments: true, AutoRuleDescriptions: autoassess.RuleDescriptions(),
	}
	with, err := reports.GenerateVulnerabilitySummary(ctx, req)
	if err != nil {
		t.Fatalf("with section: %v", err)
	}
	req.IncludeAutoAssessments = false
	without, err := reports.GenerateVulnerabilitySummary(ctx, req)
	if err != nil {
		t.Fatalf("without section: %v", err)
	}
	if !bytes.HasPrefix(with, []byte("%PDF")) || len(with) <= len(without) {
		t.Errorf("the section should add content: %d vs %d bytes", len(with), len(without))
	}
	if path := os.Getenv("VULTRACK_REPORT_OUT"); path != "" {
		if err := os.WriteFile(path, with, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("scoped to the report's servers", func(t *testing.T) {
		req.IncludeAutoAssessments = true
		req.ServerIDs = []int64{ids[0]}
		if _, err := reports.GenerateVulnerabilitySummary(ctx, req); err != nil {
			t.Fatal(err)
		}
	})
}
