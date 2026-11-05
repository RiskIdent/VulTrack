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
	SettingAutoFactSettle   = "auto_assessment_fact_settle_minutes"
	SettingAutoUnusedDays   = "auto_assessment_unused_days"
)

// DefaultUnusedDays is how long R-UNUSED needs a package to be observed
// unused; two weeks so that weekly jobs are seen at least once.
const DefaultUnusedDays = 14

// DefaultFactSettleMinutes is how long runtime facts must stay unchanged
// before a rule that reads them may create a new decision.
const DefaultFactSettleMinutes = 120

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
	// FactSettleMinutes: a rule that reads runtime facts creates a new decision
	// only when the facts it reads have not changed for this long, so a module
	// that is loaded now and then does not make decisions come and go.
	// Existing decisions are kept while the rule still holds.
	FactSettleMinutes int `json:"factSettleMinutes"`
	// UnusedDays: R-UNUSED needs a gap-free usage observation of this many
	// days during which the package was not in use.
	UnusedDays int `json:"unusedDays"`
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

		FactSettleMinutes: DefaultFactSettleMinutes,
		UnusedDays:        DefaultUnusedDays,
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
		case SettingAutoFactSettle:
			if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 7*24*60 {
				cfg.FactSettleMinutes = n
			}
		case SettingAutoUnusedDays:
			if n, err := strconv.Atoi(v); err == nil && n >= 7 && n <= 90 {
				cfg.UnusedDays = n
			}
		}
	}
	return cfg, nil
}
