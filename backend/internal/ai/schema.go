package ai

import (
	"fmt"

	"github.com/vultrack/vultrack/internal/models"
)

// schemaVersion is bumped whenever the output schema below changes. It feeds
// into the prompt hash so existing assessments can be detected as stale.
const schemaVersion = "1"

// AssessmentInput holds the CVE facts sent to the model as the user message.
type AssessmentInput struct {
	CVEID            string
	Description      string
	CVSS3Score       float64
	CVSS3Vector      string
	Severity         string
	CWEIDs           []string
	PackageName      string
	PackageVersion   string
	FixAvailable     bool
	VexStatus        string
	ExploitAvailable bool
	AffectedServers  int
}

// AssessmentResult is the structured output returned by the model. The JSON
// tags match the schema enforced via the structured-outputs API.
type AssessmentResult struct {
	AttackVector            string `json:"attack_vector"`
	Prerequisites           string `json:"prerequisites"`
	RecommendedStatus       string `json:"recommended_status"`
	RecommendationReasoning string `json:"recommendation_reasoning"`
	Confidence              string `json:"confidence"`
}

// outputSchema is the JSON schema the model output is constrained to. Structured
// outputs guarantee schema-valid JSON; Validate adds a defensive enum check.
var outputSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"attack_vector": map[string]any{
			"type":        "string",
			"description": "A few plain sentences explaining how the attack works.",
		},
		"prerequisites": map[string]any{
			"type":        "string",
			"description": "The conditions that must hold for the attack to succeed.",
		},
		"recommended_status": map[string]any{
			"type":        "string",
			"enum":        []string{models.AssessmentStatusRelevant, models.AssessmentStatusNotRelevant, models.AssessmentStatusAcceptedRisk},
			"description": "The assessment status the model recommends.",
		},
		"recommendation_reasoning": map[string]any{
			"type":        "string",
			"description": "A short justification for the recommended status.",
		},
		"confidence": map[string]any{
			"type":        "string",
			"enum":        []string{models.AIConfidenceLow, models.AIConfidenceMedium, models.AIConfidenceHigh},
			"description": "The model's confidence in its recommendation.",
		},
	},
	"required":             []string{"attack_vector", "prerequisites", "recommended_status", "recommendation_reasoning", "confidence"},
	"additionalProperties": false,
}

// Validate checks the enum fields server-side as defense in depth, in case the
// model output ever slips past the structured-output constraint.
func (r AssessmentResult) Validate() error {
	switch r.RecommendedStatus {
	case models.AssessmentStatusRelevant, models.AssessmentStatusNotRelevant, models.AssessmentStatusAcceptedRisk:
	default:
		return fmt.Errorf("invalid recommended_status %q", r.RecommendedStatus)
	}
	switch r.Confidence {
	case models.AIConfidenceLow, models.AIConfidenceMedium, models.AIConfidenceHigh:
	default:
		return fmt.Errorf("invalid confidence %q", r.Confidence)
	}
	if r.AttackVector == "" {
		return fmt.Errorf("empty attack_vector")
	}
	return nil
}
