package services

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// Automated assessment modes, globally and per rule.
const (
	AutoModeOff    = "off"    // not evaluated; stored decisions are ignored
	AutoModeShadow = "shadow" // evaluated and shown, never applied
	AutoModeActive = "active" // evaluated and applied
)

// Settings keys of the automated assessment.
const (
	SettingAutoMode         = "auto_assessment_mode"
	SettingAutoRuleModes    = "auto_assessment_rule_modes"
	SettingAutoGuardExploit = "auto_assessment_guard_exploit"
	SettingAutoGuardEPSS    = "auto_assessment_guard_epss"
)

// DefaultEPSSGuard is the EPSS probability at or above which automated
// dismissal is blocked, when the setting is missing or invalid.
const DefaultEPSSGuard = 0.1

// AutoAssessmentConfig is the admin configuration of the automated assessment.
// It is the single source of truth for the evaluator, the triage queue, the UI
// and MCP.
type AutoAssessmentConfig struct {
	Mode      string            `json:"mode"`
	RuleModes map[string]string `json:"ruleModes"` // rules not listed run in shadow mode
	// GuardExploit blocks dismissal of CVEs with a verified ExploitDB exploit.
	GuardExploit bool `json:"guardExploit"`
	// GuardEPSS blocks dismissal of CVEs with an EPSS score >= this value; 0 = off.
	GuardEPSS float64 `json:"guardEpss"`
}

// RuleMode returns the effective mode of a rule. With the global mode off or in
// shadow, no rule is active.
func (c AutoAssessmentConfig) RuleMode(ruleID string) string {
	switch c.Mode {
	case AutoModeOff:
		return AutoModeOff
	case AutoModeShadow:
		if c.RuleModes[ruleID] == AutoModeOff {
			return AutoModeOff
		}
		return AutoModeShadow
	}
	switch m := c.RuleModes[ruleID]; m {
	case AutoModeOff, AutoModeActive:
		return m
	}
	return AutoModeShadow
}

// ActiveRuleIDs lists the rules whose decisions take effect, sorted. Empty
// unless the global mode is active.
func (c AutoAssessmentConfig) ActiveRuleIDs() []string {
	ids := []string{}
	if c.Mode != AutoModeActive {
		return ids
	}
	for id, m := range c.RuleModes {
		if m == AutoModeActive {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// LoadAutoAssessmentConfig reads the configuration from settings. Missing or
// invalid values fall back to the safe defaults: shadow mode, all guards on.
func (s *SettingsService) LoadAutoAssessmentConfig(ctx context.Context) (AutoAssessmentConfig, error) {
	cfg := AutoAssessmentConfig{
		Mode:         AutoModeShadow,
		RuleModes:    map[string]string{},
		GuardExploit: true,
		GuardEPSS:    DefaultEPSSGuard,
	}
	all, err := s.GetAll(ctx)
	if err != nil {
		return cfg, err
	}
	for _, st := range all {
		v := strings.TrimSpace(st.Value)
		switch st.Key {
		case SettingAutoMode:
			if v == AutoModeOff || v == AutoModeShadow || v == AutoModeActive {
				cfg.Mode = v
			}
		case SettingAutoRuleModes:
			var modes map[string]string
			if json.Unmarshal([]byte(v), &modes) == nil {
				for id, m := range modes {
					if m == AutoModeOff || m == AutoModeShadow || m == AutoModeActive {
						cfg.RuleModes[id] = m
					}
				}
			}
		case SettingAutoGuardExploit:
			cfg.GuardExploit = v != "false"
		case SettingAutoGuardEPSS:
			if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && f <= 1 {
				cfg.GuardEPSS = f
			}
		}
	}
	return cfg, nil
}
