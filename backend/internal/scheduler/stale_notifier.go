package scheduler

import (
	"context"
	"fmt"
	"html"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/models"
	"github.com/vultrack/vultrack/internal/services"
)

// StaleNotifier emails the list of servers without agent reports, once a day
// from the configured hour on, and only when there is at least one: a mail
// without warnings is never sent.
type StaleNotifier struct {
	settings *services.SettingsService
	servers  *services.ServerService
	email    mailer

	// now is the clock; tests replace it.
	now func() time.Time

	mu     sync.Mutex
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// mailer is the part of services.EmailService the notifier uses.
type mailer interface {
	IsEnabled() bool
	SendEmail(to []string, subject, htmlBody, textBody string) error
}

// NewStaleNotifier creates a StaleNotifier.
func NewStaleNotifier(settings *services.SettingsService, servers *services.ServerService, email mailer) *StaleNotifier {
	return &StaleNotifier{settings: settings, servers: servers, email: email, now: time.Now, stopCh: make(chan struct{})}
}

// Start checks every ten minutes.
func (n *StaleNotifier) Start() {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-n.stopCh:
				return
			case <-t.C:
				if _, err := n.CheckAndSend(context.Background()); err != nil {
					log.Error().Err(err).Msg("Stale server email failed")
				}
			}
		}
	}()
}

// Stop stops the schedule.
func (n *StaleNotifier) Stop() {
	close(n.stopCh)
	n.wg.Wait()
}

// CheckAndSend sends today's email if it is due and there are stale servers.
// It returns the number of servers reported (0 = nothing sent).
func (n *StaleNotifier) CheckAndSend(ctx context.Context) (int, error) {
	cfg, err := n.settings.LoadStaleConfig(ctx)
	if err != nil {
		return 0, err
	}
	if !cfg.EmailEnabled || cfg.Hours == 0 || len(cfg.EmailTo) == 0 || !n.email.IsEnabled() {
		return 0, nil
	}
	now := n.now()
	if now.Hour() < cfg.EmailHour {
		return 0, nil
	}
	today := now.Format("2006-01-02")
	if last, _ := n.settings.GetValue(ctx, services.SettingStaleEmailLastSent); last == today {
		return 0, nil
	}
	return n.send(ctx, cfg, today)
}

// SendNow sends the email immediately if there are stale servers, whatever
// the hour and whether one was sent today. Used by "Send now" in Admin.
func (n *StaleNotifier) SendNow(ctx context.Context) (int, error) {
	cfg, err := n.settings.LoadStaleConfig(ctx)
	if err != nil {
		return 0, err
	}
	if cfg.Hours == 0 {
		return 0, fmt.Errorf("stale-server warnings are off")
	}
	if len(cfg.EmailTo) == 0 {
		return 0, fmt.Errorf("no recipients configured")
	}
	if !n.email.IsEnabled() {
		return 0, fmt.Errorf("email is not configured (SMTP)")
	}
	return n.send(ctx, cfg, n.now().Format("2006-01-02"))
}

func (n *StaleNotifier) send(ctx context.Context, cfg services.StaleConfig, today string) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	stale, err := n.servers.StaleServers(ctx, cfg.Threshold())
	if err != nil {
		return 0, err
	}
	if len(stale) == 0 {
		return 0, nil // no warnings, no mail
	}
	subject, htmlBody, textBody := staleEmail(stale, cfg.Hours)
	if err := n.email.SendEmail(cfg.EmailTo, subject, htmlBody, textBody); err != nil {
		return 0, err
	}
	if err := n.settings.Set(ctx, services.SettingStaleEmailLastSent, today); err != nil {
		return len(stale), err
	}
	log.Info().Int("servers", len(stale)).Strs("to", cfg.EmailTo).Msg("Stale server email sent")
	return len(stale), nil
}

// humanAge renders a duration as "3 days 4 h" or "26 h".
func humanAge(seconds float64) string {
	h := int(seconds / 3600)
	if h < 48 {
		return fmt.Sprintf("%d h", h)
	}
	return fmt.Sprintf("%d days %d h", h/24, h%24)
}

func staleEmail(stale []models.Server, hours int) (subject, htmlBody, textBody string) {
	subject = fmt.Sprintf("VulTrack: %d server(s) without agent report for more than %d h", len(stale), hours)
	var hb, tb strings.Builder
	fmt.Fprintf(&hb, `<p>These servers have not sent an agent report for more than %d hours. Their findings may be out of date.</p>`, hours)
	hb.WriteString(`<table cellpadding="6" style="border-collapse:collapse;font-family:sans-serif;font-size:14px">` +
		`<tr style="text-align:left;border-bottom:1px solid #ccc"><th>Server</th><th>Last report</th><th>Silent for</th><th>OS</th></tr>`)
	fmt.Fprintf(&tb, "These servers have not sent an agent report for more than %d hours. Their findings may be out of date.\n\n", hours)
	for _, s := range stale {
		last := "never"
		if s.LastReportAt != nil {
			last = s.LastReportAt.Format("2006-01-02 15:04") + " UTC"
		}
		fmt.Fprintf(&hb, `<tr style="border-bottom:1px solid #eee"><td>%s</td><td>%s</td><td>%s</td><td>%s %s</td></tr>`,
			html.EscapeString(s.Name), last, humanAge(s.ReportAgeSeconds), html.EscapeString(s.OSFamily), html.EscapeString(s.OSRelease))
		fmt.Fprintf(&tb, "- %s: last report %s (%s ago), %s %s\n", s.Name, last, humanAge(s.ReportAgeSeconds), s.OSFamily, s.OSRelease)
	}
	hb.WriteString(`</table><p>Servers that were switched off on purpose can be marked as disabled in VulTrack under ` +
		`Admin &rarr; Servers; they are then no longer reported.</p>`)
	tb.WriteString("\nServers that were switched off on purpose can be marked as disabled in VulTrack under Admin -> Servers; they are then no longer reported.\n")
	return subject, hb.String(), tb.String()
}
