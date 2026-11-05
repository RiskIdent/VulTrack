package autoassess

import (
	"strconv"

	"github.com/vultrack/vultrack/internal/services"
)

// RuleInfo describes a rule of the catalogue with its configured mode.
type RuleInfo struct {
	ID            string `json:"id"`
	Version       int    `json:"version"`
	Description   string `json:"description"`
	Mode          string `json:"mode"`          // configured: off, shadow, active
	EffectiveMode string `json:"effectiveMode"` // after the global mode
}

// GuardInfo describes a guard.
type GuardInfo struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// Info assembles the configuration with the rule catalogue. It is
// shared by the REST API and the MCP interface.
func Info(cfg services.AutoAssessmentConfig) map[string]any {
	rules := make([]RuleInfo, 0, len(Rules))
	for _, r := range Rules {
		mode := cfg.RuleModes[r.ID()]
		if mode == "" {
			mode = services.AutoModeShadow
		}
		rules = append(rules, RuleInfo{ID: r.ID(), Version: r.Version(), Description: r.Description(),
			Mode: mode, EffectiveMode: cfg.RuleMode(r.ID())})
	}
	guards := []GuardInfo{
		{"G-KEV", GuardDescriptions["G-KEV"], true},
		{"G-EXPLOIT", GuardDescriptions["G-EXPLOIT"], cfg.GuardExploit},
		{"G-EPSS", GuardDescriptions["G-EPSS"], cfg.GuardEPSS > 0},
	}
	return map[string]any{
		"mode":              cfg.Mode,
		"rules":             rules,
		"guards":            guards,
		"guardExploit":      cfg.GuardExploit,
		"guardEpss":         cfg.GuardEPSS,
		"factSettleMinutes": cfg.FactSettleMinutes,
		"unusedDays":        cfg.UnusedDays,
		"activeRules":       cfg.ActiveRuleIDs(),
	}
}

// RuleDescriptions maps every rule ID to its description.
func RuleDescriptions() map[string]string {
	out := make(map[string]string, len(Rules))
	for _, r := range Rules {
		out[r.ID()] = "v" + strconv.Itoa(r.Version()) + ": " + r.Description()
	}
	return out
}
