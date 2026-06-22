package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// baseInstruction is the fixed framing of the task. It is prepended to the
// admin-configured infrastructure context so that editing the admin prompt can
// never break the output contract. It is not editable from the UI.
const baseInstruction = `You are a vulnerability triage assistant for an infrastructure security team.
For the CVE described in the user message, explain in a few simple sentences what the attack vector is — how the attack works and what preconditions it requires — and recommend an assessment status.

Recommend exactly one status:
- "relevant": the vulnerability is exploitable and matters for this infrastructure; it should be remediated.
- "not_relevant": the vulnerability does not apply or cannot be exploited in this infrastructure.
- "accepted_risk": the vulnerability applies but the residual risk is acceptable in this context.

Your recommendation is advisory only; a human analyst makes the final decision. Base your reasoning on the provided CVE facts and the infrastructure context below. If information is missing, say so rather than guessing.`

// DefaultInfraContext is the starting infrastructure context seeded into the
// admin-editable ai_system_prompt setting. Admins replace it with a description
// of their own infrastructure, critical attack vectors, and acceptable scenarios.
const DefaultInfraContext = `Infrastructure context:
- Describe your infrastructure here (e.g. internet-facing services, internal-only services, operating systems, key software).
- Note which attack vectors are especially critical for this environment.
- Note which scenarios are acceptable risks (e.g. vulnerabilities only exploitable with local access on isolated hosts).`

// BuildSystemPrompt combines the fixed task framing with the admin-configured
// infrastructure context into the effective system prompt.
func BuildSystemPrompt(infraContext string) string {
	infraContext = strings.TrimSpace(infraContext)
	if infraContext == "" {
		infraContext = DefaultInfraContext
	}
	return baseInstruction + "\n\n" + infraContext
}

// PromptHash returns a stable hash of the effective system prompt, model, and
// schema version. A change in any of these marks existing assessments as stale.
func PromptHash(systemPrompt, model string) string {
	sum := sha256.Sum256([]byte(systemPrompt + "\x00" + model + "\x00" + schemaVersion))
	return hex.EncodeToString(sum[:])
}

// buildUserMessage renders the CVE facts into the user message sent to the model.
func buildUserMessage(in AssessmentInput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CVE ID: %s\n", in.CVEID)
	if in.Severity != "" {
		fmt.Fprintf(&b, "Severity: %s\n", in.Severity)
	}
	if in.CVSS3Score > 0 {
		fmt.Fprintf(&b, "CVSS v3 score: %.1f\n", in.CVSS3Score)
	}
	if in.CVSS3Vector != "" {
		fmt.Fprintf(&b, "CVSS v3 vector: %s\n", in.CVSS3Vector)
	}
	if len(in.CWEIDs) > 0 {
		fmt.Fprintf(&b, "CWE: %s\n", strings.Join(in.CWEIDs, ", "))
	}
	if in.PackageName != "" {
		fmt.Fprintf(&b, "Affected package: %s %s\n", in.PackageName, in.PackageVersion)
	}
	fmt.Fprintf(&b, "Fix available: %t\n", in.FixAvailable)
	fmt.Fprintf(&b, "Public exploit known: %t\n", in.ExploitAvailable)
	if in.VexStatus != "" {
		fmt.Fprintf(&b, "VEX status: %s\n", in.VexStatus)
	}
	fmt.Fprintf(&b, "Affected servers in this environment: %d\n", in.AffectedServers)
	if in.Description != "" {
		fmt.Fprintf(&b, "\nDescription:\n%s\n", in.Description)
	}
	return b.String()
}
