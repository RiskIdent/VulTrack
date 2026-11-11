package scheduler

// Stale servers: report time, disabled servers, triage exclusion and the
// daily email that is only sent when there is something to report.
//
// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"strings"
	"testing"
	"time"

	"github.com/vultrack/vultrack/internal/models"
	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

type fakeMailer struct {
	sent []string // subjects
	body string
}

func (f *fakeMailer) IsEnabled() bool { return true }
func (f *fakeMailer) SendEmail(to []string, subject, htmlBody, textBody string) error {
	f.sent = append(f.sent, subject)
	f.body = textBody
	return nil
}

func TestStaleServers(t *testing.T) {
	pool, ctx := testdb.Setup(t, "stale_server_tests")
	settings := services.NewSettingsService(pool)
	servers := services.NewServerService(pool)
	findings := services.NewFindingService(pool)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}

	// Reports set last_report_at.
	ids := map[string]int64{}
	for _, name := range []string{"fresh", "silent", "off"} {
		srv, err := servers.Upsert(ctx, &models.Server{Name: name, OSFamily: "ubuntu", OSRelease: "24.04", IPv4Addrs: []string{}})
		if err != nil {
			t.Fatal(err)
		}
		ids[name] = srv.ID
		exec(`INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state, severity, source_type, cvss3_score, first_seen_at, last_seen_at)
		      VALUES ($1, 'CVE-1', 'p', '1', 'affected', 'high', 'usn', 9.0, NOW(), NOW())`, srv.ID)
	}
	exec(`UPDATE servers SET last_report_at = NOW() - interval '30 hours' WHERE name IN ('silent', 'off')`)
	if err := servers.SetDisabled(ctx, ids["off"], true, "admin@example.com"); err != nil {
		t.Fatal(err)
	}

	stale, err := servers.StaleServers(ctx, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 1 || stale[0].Name != "silent" || stale[0].ReportAgeSeconds < 29*3600 {
		t.Fatalf("stale servers %+v", stale)
	}
	all, err := servers.GetAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := settings.LoadStaleConfig(ctx)
	cfg.MarkStale(all)
	for _, s := range all {
		if want := s.Name == "silent"; s.Stale != want {
			t.Errorf("%s: stale=%v", s.Name, s.Stale)
		}
		if s.Name == "off" && (s.DisabledAt == nil || s.DisabledBy != "admin@example.com") {
			t.Errorf("disabled server %+v", s)
		}
	}

	// Disabled servers are not in the triage queue.
	opts, _ := settings.BuildTriageOptions(ctx)
	opts.Limit = 10
	q, _, err := findings.GetTriageQueue(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range q {
		if f.ServerID == ids["off"] {
			t.Error("a disabled server's finding is in the triage queue")
		}
	}

	// Email: off by default, then only with stale servers, once a day, from the hour on.
	mail := &fakeMailer{}
	n := NewStaleNotifier(settings, servers, mail)
	clock := time.Date(2026, 11, 11, 7, 0, 0, 0, time.Local)
	n.now = func() time.Time { return clock }
	run := func() int {
		t.Helper()
		k, err := n.CheckAndSend(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	if run() != 0 || len(mail.sent) != 0 {
		t.Fatal("email sent while disabled")
	}
	if err := settings.SetMultiple(ctx, map[string]string{services.SettingStaleEmailEnabled: "true",
		services.SettingStaleEmailTo: "ops@example.com", services.SettingStaleEmailHour: "8"}); err != nil {
		t.Fatal(err)
	}
	if run() != 0 {
		t.Error("sent before the configured hour")
	}
	clock = clock.Add(2 * time.Hour)
	if run() != 1 || len(mail.sent) != 1 || !strings.Contains(mail.body, "silent") || strings.Contains(mail.body, "off:") {
		t.Fatalf("first email: %v %q", mail.sent, mail.body)
	}
	if run() != 0 || len(mail.sent) != 1 {
		t.Error("second email on the same day")
	}

	// Next day, nothing stale: no email.
	exec(`UPDATE servers SET last_report_at = NOW()`)
	clock = clock.Add(24 * time.Hour)
	if run() != 0 || len(mail.sent) != 1 {
		t.Error("an email without stale servers was sent")
	}
	// Send now with nothing stale: nothing sent, no error.
	if k, err := n.SendNow(ctx); err != nil || k != 0 || len(mail.sent) != 1 {
		t.Errorf("send now without stale servers: %d %v", k, err)
	}
}
