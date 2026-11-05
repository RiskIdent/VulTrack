package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
)

// Precondition analysis (docs/AUTO_ASSESSMENT_PLAN.md §8.1): the model lists,
// per CVE, the alternative attack paths and the conditions each one needs, in
// a closed vocabulary. VulTrack checks those conditions per server against the
// agent's runtime facts; the model never decides about a server itself.

// preconditionSchemaVersion is bumped whenever the schema or prompt below
// changes; it is part of the prompt hash, so every analysis is redone.
const preconditionSchemaVersion = "1"

// preconditionMaxTokens leaves room for adaptive thinking; batches have no
// request timeout and the synchronous path stays below the non-streaming limit.
const preconditionMaxTokens = 16000

// Condition types. Only the checkable ones can ever dismiss a server.
const (
	CondNetworkListener    = "network_listener"    // a process of Package listens (Scope: any or non_loopback)
	CondPackageInUse       = "package_in_use"      // code of Package must run in some process
	CondServiceActive      = "service_active"      // a systemd service of Package (or Unit) must run
	CondUnprivilegedUserns = "unprivileged_userns" // unprivileged users can create user namespaces
	CondUnprivilegedBPF    = "unprivileged_bpf"    // unprivileged users can load BPF programs
	CondKernelCode         = "kernel_code"         // kernel source file Path must be compiled in
	CondLocalUser          = "local_user"          // attacker needs a local account
	CondPhysicalAccess     = "physical_access"
	CondUserInteraction    = "user_interaction"
	CondConfigDependent    = "config_dependent" // a configuration the system cannot check (free text)
)

// ConditionTypes is the closed vocabulary.
var ConditionTypes = []string{
	CondNetworkListener, CondPackageInUse, CondServiceActive, CondUnprivilegedUserns, CondUnprivilegedBPF,
	CondKernelCode, CondLocalUser, CondPhysicalAccess, CondUserInteraction, CondConfigDependent,
}

// Condition is one requirement of an attack path.
type Condition struct {
	Type       string `json:"type"`
	Package    string `json:"package"` // Debian binary package, "" if not applicable
	Unit       string `json:"unit"`    // systemd unit, "" if not applicable
	Path       string `json:"path"`    // kernel source path, "" if not applicable
	Scope      string `json:"scope"`   // network_listener: "any" or "non_loopback"; else ""
	Necessary  bool   `json:"necessary"`
	Confidence string `json:"confidence"` // low, medium, high
	Reason     string `json:"reason"`
}

// AttackPath is one way to exploit the CVE; all its conditions are needed.
type AttackPath struct {
	Requires []Condition `json:"requires"`
}

// PreconditionResult is the model's structured output.
type PreconditionResult struct {
	Determinable                 bool         `json:"determinable"`
	Paths                        []AttackPath `json:"paths"`
	Reasoning                    string       `json:"reasoning"`
	RecommendedStatusIfReachable string       `json:"recommended_status_if_reachable"`
}

var preconditionSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"determinable": map[string]any{
			"type":        "boolean",
			"description": "false when the CVE data does not allow naming the preconditions with confidence.",
		},
		"paths": map[string]any{
			"type":        "array",
			"description": "Alternative attack paths; any single one suffices for an attack.",
			"items": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"requires": map[string]any{
						"type":        "array",
						"description": "Conditions that must all hold for this path.",
						"items": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"type":       map[string]any{"type": "string", "enum": ConditionTypes},
								"package":    map[string]any{"type": "string"},
								"unit":       map[string]any{"type": "string"},
								"path":       map[string]any{"type": "string"},
								"scope":      map[string]any{"type": "string", "enum": []string{"", "any", "non_loopback"}},
								"necessary":  map[string]any{"type": "boolean"},
								"confidence": map[string]any{"type": "string", "enum": []string{"low", "medium", "high"}},
								"reason":     map[string]any{"type": "string"},
							},
							"required":             []string{"type", "package", "unit", "path", "scope", "necessary", "confidence", "reason"},
							"additionalProperties": false,
						},
					},
				},
				"required":             []string{"requires"},
				"additionalProperties": false,
			},
		},
		"reasoning": map[string]any{"type": "string"},
		"recommended_status_if_reachable": map[string]any{
			"type": "string", "enum": []string{"relevant", "accepted_risk"},
		},
	},
	"required":             []string{"determinable", "paths", "reasoning", "recommended_status_if_reachable"},
	"additionalProperties": false,
}

// Validate is defense in depth behind the structured-output constraint.
func (r PreconditionResult) Validate() error {
	valid := map[string]bool{}
	for _, t := range ConditionTypes {
		valid[t] = true
	}
	for i, p := range r.Paths {
		if len(p.Requires) == 0 {
			return fmt.Errorf("path %d has no conditions", i+1)
		}
		for _, c := range p.Requires {
			if !valid[c.Type] {
				return fmt.Errorf("unknown condition type %q", c.Type)
			}
			switch c.Confidence {
			case "low", "medium", "high":
			default:
				return fmt.Errorf("invalid confidence %q", c.Confidence)
			}
			// A network_listener, package_in_use or service_active without a
			// package (or unit) means "any program": valid, but never
			// checkable, so it can never dismiss a server.
		}
	}
	return nil
}

const preconditionInstruction = `You analyse a CVE for an automated vulnerability triage system that runs on Ubuntu/Debian servers.

Your task is not to decide whether the CVE is relevant. List the ways it can be exploited ("paths") and, for each path, the conditions an attacker needs. The system checks those conditions on every server against facts collected there (listening sockets with their owning Debian package, packages mapped by running processes, systemd services, kernel sysctls) and dismisses the CVE on a server only when every path contains a necessary, high-confidence condition that is definitely false there. A wrong "necessary" or "high" can hide a real vulnerability; an omitted path can too. When in doubt, lower the confidence or mark the condition as not necessary; the CVE then stays open for a human, which is always safe.

Rules:
- paths are alternatives: list every realistic way to exploit the CVE, including local ones (e.g. a local user running a vulnerable setuid program) next to remote ones. If one path needs nothing checkable, the CVE can never be dismissed, and that is correct.
- requires lists all conditions of one path. Use only these types:
  - network_listener: a process of the Debian binary package in "package" must listen on a socket. scope "non_loopback" when the attack needs network access from other hosts, "any" when a local connection suffices. Name the package whose process listens (e.g. "openssh-server" for a libssl flaw reachable through sshd); add one path per server package that could expose the vulnerable code, or a package_in_use condition if any process using the library could be attacked.
  - package_in_use: code from the Debian binary package in "package" must run in some process (a library loaded, a program executed).
  - service_active: a systemd service from "package" (or the unit in "unit") must be running.
  - unprivileged_userns: unprivileged users must be able to create user namespaces.
  - unprivileged_bpf: unprivileged users must be able to load BPF programs.
  - kernel_code: the kernel source file in "path" (relative to the kernel tree) must be compiled into the running kernel.
  - local_user: the attacker needs a local account or code execution as a local user.
  - physical_access, user_interaction: as named.
  - config_dependent: anything else (a configuration option, a specific use of a feature); explain it in "reason". It is never checked.
- necessary: true only if the path cannot work at all without the condition.
- confidence: "high" only if the CVE data clearly supports it; otherwise "medium" or "low".
- Use the exact Debian binary package names from the affected packages list when the condition is about them; leave package, unit, path and scope empty ("") when they do not apply.
- determinable: false when the description is too vague to name the preconditions; then return the paths you can, they will not be used.
- reasoning: a few sentences a security analyst can check.
- recommended_status_if_reachable: "relevant", or "accepted_risk" only when even a reachable instance is clearly harmless.`

// PreconditionPromptHash identifies prompt, schema and model of an analysis.
func PreconditionPromptHash(model string) string {
	sum := sha256.Sum256([]byte(preconditionInstruction + "\x00" + model + "\x00" + preconditionSchemaVersion))
	return hex.EncodeToString(sum[:])
}

// PreconditionInput is the CVE data sent to the model.
type PreconditionInput struct {
	CVEID       string         `json:"cveId"`
	Description string         `json:"description"`
	CVSS3Score  float64        `json:"cvss3Score,omitempty"`
	CVSS3Vector string         `json:"cvss3Vector,omitempty"`
	CWEIDs      []string       `json:"cweIds,omitempty"`
	Packages    []InputPackage `json:"packages"` // affected Debian binary packages
	Kernel      bool           `json:"kernel"`   // a finding of the running kernel
}

// InputPackage is one affected package.
type InputPackage struct {
	Name   string `json:"name"`
	Source string `json:"source,omitempty"`
}

// Hash identifies the input; a changed description or package list redoes
// the analysis.
func (in PreconditionInput) Hash() string {
	b, _ := json.Marshal(in)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (in PreconditionInput) userMessage() string {
	var b strings.Builder
	fmt.Fprintf(&b, "CVE ID: %s\n", in.CVEID)
	if in.CVSS3Score > 0 {
		fmt.Fprintf(&b, "CVSS v3 score: %.1f\n", in.CVSS3Score)
	}
	if in.CVSS3Vector != "" {
		fmt.Fprintf(&b, "CVSS v3 vector: %s\n", in.CVSS3Vector)
	}
	if len(in.CWEIDs) > 0 {
		fmt.Fprintf(&b, "CWE: %s\n", strings.Join(in.CWEIDs, ", "))
	}
	if in.Kernel {
		b.WriteString("Affected component: the Linux kernel (running kernel of the servers)\n")
	}
	if len(in.Packages) > 0 {
		b.WriteString("Affected Debian binary packages on the servers:\n")
		for _, p := range in.Packages {
			if p.Source != "" && p.Source != p.Name {
				fmt.Fprintf(&b, "- %s (source package %s)\n", p.Name, p.Source)
			} else {
				fmt.Fprintf(&b, "- %s\n", p.Name)
			}
		}
	}
	fmt.Fprintf(&b, "\nDescription:\n%s\n", strings.TrimSpace(in.Description))
	return b.String()
}

// Usage is the token usage of one analysis.
type Usage struct {
	InputTokens         int64
	OutputTokens        int64
	CacheReadTokens     int64
	CacheCreationTokens int64
}

func usageOf(u anthropic.Usage) Usage {
	return Usage{InputTokens: u.InputTokens, OutputTokens: u.OutputTokens,
		CacheReadTokens: u.CacheReadInputTokens, CacheCreationTokens: u.CacheCreationInputTokens}
}

// preconditionParams builds the request. The instruction is cached: it is
// identical for every CVE.
func preconditionParams(model string, in PreconditionInput) anthropic.MessageNewParams {
	return anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: preconditionMaxTokens,
		System: []anthropic.TextBlockParam{{
			Text:         preconditionInstruction,
			CacheControl: anthropic.NewCacheControlEphemeralParam(),
		}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(in.userMessage())),
		},
		OutputConfig: anthropic.OutputConfigParam{
			Format: anthropic.JSONOutputFormatParam{Schema: preconditionSchema},
		},
	}
}

// parsePrecondition reads a model response.
func parsePrecondition(msg *anthropic.Message) (PreconditionResult, error) {
	switch msg.StopReason {
	case anthropic.StopReasonRefusal:
		return PreconditionResult{}, fmt.Errorf("%w (category %q: %s)", ErrRefusal,
			string(msg.StopDetails.Category), msg.StopDetails.Explanation)
	case anthropic.StopReasonMaxTokens:
		return PreconditionResult{}, ErrIncompleteOutput
	case anthropic.StopReasonModelContextWindowExceeded:
		return PreconditionResult{}, ErrContextTooLarge
	}
	var text strings.Builder
	for _, block := range msg.Content {
		if block.Type == "text" {
			text.WriteString(block.Text)
		}
	}
	var r PreconditionResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(text.String())), &r); err != nil {
		return PreconditionResult{}, fmt.Errorf("%w: parse: %v", ErrBadOutput, err)
	}
	if err := r.Validate(); err != nil {
		return PreconditionResult{}, fmt.Errorf("%w: %v", ErrBadOutput, err)
	}
	return r, nil
}

// AnalyzePreconditions runs one analysis synchronously.
func (c *Client) AnalyzePreconditions(ctx context.Context, model string, in PreconditionInput) (PreconditionResult, Usage, error) {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	msg, err := c.api.Messages.New(ctx, preconditionParams(model, in))
	if err != nil {
		return PreconditionResult{}, Usage{}, fmt.Errorf("anthropic request: %w", err)
	}
	r, err := parsePrecondition(msg)
	return r, usageOf(msg.Usage), err
}

// BatchItem is one CVE of a batch; CustomID must be unique within it.
type BatchItem struct {
	CustomID string
	Input    PreconditionInput
}

// SubmitPreconditionBatch creates a Message Batch (50 % price, results within
// 24 hours) and returns its id.
func (c *Client) SubmitPreconditionBatch(ctx context.Context, model string, items []BatchItem) (string, error) {
	reqs := make([]anthropic.MessageBatchNewParamsRequest, 0, len(items))
	for _, it := range items {
		p := preconditionParams(model, it.Input)
		reqs = append(reqs, anthropic.MessageBatchNewParamsRequest{
			CustomID: it.CustomID,
			Params: anthropic.MessageBatchNewParamsRequestParams{
				Model: p.Model, MaxTokens: p.MaxTokens, System: p.System, Messages: p.Messages, OutputConfig: p.OutputConfig,
			},
		})
	}
	b, err := c.api.Messages.Batches.New(ctx, anthropic.MessageBatchNewParams{Requests: reqs})
	if err != nil {
		return "", fmt.Errorf("create batch: %w", err)
	}
	return b.ID, nil
}

// BatchOutcome is the result of one batch request.
type BatchOutcome struct {
	CustomID string
	Result   PreconditionResult
	Usage    Usage
	Err      error
}

// PreconditionBatchResults returns the outcomes once the batch has ended;
// done is false while it is still processing.
func (c *Client) PreconditionBatchResults(ctx context.Context, batchID string) (done bool, out []BatchOutcome, err error) {
	b, err := c.api.Messages.Batches.Get(ctx, batchID)
	if err != nil {
		return false, nil, fmt.Errorf("get batch: %w", err)
	}
	if b.ProcessingStatus != anthropic.MessageBatchProcessingStatusEnded {
		return false, nil, nil
	}
	stream := c.api.Messages.Batches.ResultsStreaming(ctx, batchID)
	defer stream.Close()
	for stream.Next() {
		r := stream.Current()
		o := BatchOutcome{CustomID: r.CustomID}
		switch r.Result.Type {
		case "succeeded":
			msg := r.Result.AsSucceeded().Message
			o.Usage = usageOf(msg.Usage)
			o.Result, o.Err = parsePrecondition(&msg)
		case "errored":
			o.Err = fmt.Errorf("batch request failed: %s", r.Result.AsErrored().Error.RawJSON())
		default:
			o.Err = fmt.Errorf("batch request %s", r.Result.Type)
		}
		out = append(out, o)
	}
	return true, out, stream.Err()
}
