package services

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/vultrack/vultrack/internal/models"
)

// Settings of the stale-server warning.
const (
	SettingStaleHours         = "stale_server_hours"            // 0 = no warnings
	SettingStaleEmailEnabled  = "stale_server_email_enabled"    // daily email when servers are stale
	SettingStaleEmailTo       = "stale_server_email_recipients" // comma-separated
	SettingStaleEmailHour     = "stale_server_email_hour"       // 0-23, server time
	SettingStaleEmailLastSent = "stale_server_email_last_sent"  // date of the last email (internal)
)

// DefaultStaleHours is the threshold when none is configured.
const DefaultStaleHours = 24

// StaleConfig controls the stale-server warnings.
type StaleConfig struct {
	Hours        int      `json:"hours"` // 0 = off
	EmailEnabled bool     `json:"emailEnabled"`
	EmailTo      []string `json:"emailTo"`
	EmailHour    int      `json:"emailHour"`
}

// Threshold is the age of the last report after which a server is stale; 0
// when warnings are off.
func (c StaleConfig) Threshold() time.Duration {
	return time.Duration(c.Hours) * time.Hour
}

// MarkStale sets Stale on every enabled server whose last report is older
// than the threshold.
func (c StaleConfig) MarkStale(servers []models.Server) {
	for i := range servers {
		servers[i].Stale = c.Hours > 0 && servers[i].DisabledAt == nil &&
			servers[i].ReportAgeSeconds > c.Threshold().Seconds()
	}
}

// LoadStaleConfig reads the stale-server settings.
func (s *SettingsService) LoadStaleConfig(ctx context.Context) (StaleConfig, error) {
	cfg := StaleConfig{Hours: DefaultStaleHours, EmailHour: 8, EmailTo: []string{}}
	all, err := s.GetAll(ctx)
	if err != nil {
		return cfg, err
	}
	for _, st := range all {
		v := strings.TrimSpace(st.Value)
		switch st.Key {
		case SettingStaleHours:
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				cfg.Hours = n
			}
		case SettingStaleEmailEnabled:
			cfg.EmailEnabled = v == "true"
		case SettingStaleEmailTo:
			for _, r := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' }) {
				if strings.Contains(r, "@") {
					cfg.EmailTo = append(cfg.EmailTo, r)
				}
			}
		case SettingStaleEmailHour:
			if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 23 {
				cfg.EmailHour = n
			}
		}
	}
	return cfg, nil
}
