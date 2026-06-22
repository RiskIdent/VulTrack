// Package ai wraps the Anthropic API to produce advisory CVE assessments.
// It is the only place that talks to the LLM; callers pass CVE facts in and get
// a validated, structured assessment back.
package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// maxOutputTokens caps the response. The structured output is small, so this is
// generous; staying well under ~16k also keeps the request non-streaming-safe.
const maxOutputTokens = 1500

// Non-retryable assessment errors. Transient errors (network, rate limit, 5xx)
// are returned as wrapped errors and may be retried by the caller.
var (
	// ErrRefusal means the model declined the request for safety reasons.
	ErrRefusal = errors.New("model refused the request")
	// ErrIncompleteOutput means generation hit the token limit before finishing.
	ErrIncompleteOutput = errors.New("model output was truncated")
	// ErrBadOutput means the model output could not be parsed or failed validation.
	// Retrying the same input is unlikely to help, so callers treat it as terminal.
	ErrBadOutput = errors.New("model output was invalid")
)

// Client produces CVE assessments via the Anthropic API.
type Client struct {
	api       anthropic.Client
	maxTokens int64
	timeout   time.Duration
}

// New creates an AI client. timeoutSec bounds each request (0 = no extra bound).
func New(apiKey string, timeoutSec int) *Client {
	return &Client{
		api:       anthropic.NewClient(option.WithAPIKey(apiKey)),
		maxTokens: maxOutputTokens,
		timeout:   time.Duration(timeoutSec) * time.Second,
	}
}

// AssessOptions carries the per-request configuration that comes from settings
// and may change between calls.
type AssessOptions struct {
	Model        string // model id, e.g. "claude-haiku-4-5"
	InfraContext string // admin-configured infrastructure context
}

// AssessmentMeta captures provenance and cost data for a completed assessment.
type AssessmentMeta struct {
	Model        string
	PromptHash   string
	InputTokens  int
	OutputTokens int
}

// Assess sends the CVE facts to the model and returns a validated assessment.
// Meta is populated (model, prompt hash, token usage) even on most error paths
// so callers can record provenance and cost.
func (c *Client) Assess(ctx context.Context, in AssessmentInput, opts AssessOptions) (AssessmentResult, AssessmentMeta, error) {
	system := BuildSystemPrompt(opts.InfraContext)
	meta := AssessmentMeta{Model: opts.Model, PromptHash: PromptHash(system, opts.Model)}

	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	resp, err := c.api.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(opts.Model),
		MaxTokens: c.maxTokens,
		System:    []anthropic.TextBlockParam{{Text: system}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(buildUserMessage(in))),
		},
		OutputConfig: anthropic.OutputConfigParam{
			Format: anthropic.JSONOutputFormatParam{Schema: outputSchema},
		},
	})
	if err != nil {
		return AssessmentResult{}, meta, fmt.Errorf("anthropic request: %w", err)
	}

	meta.InputTokens = int(resp.Usage.InputTokens)
	meta.OutputTokens = int(resp.Usage.OutputTokens)

	switch resp.StopReason {
	case anthropic.StopReasonRefusal:
		return AssessmentResult{}, meta, ErrRefusal
	case anthropic.StopReasonMaxTokens:
		return AssessmentResult{}, meta, ErrIncompleteOutput
	}

	var text strings.Builder
	for _, block := range resp.Content {
		if block.Type == "text" {
			text.WriteString(block.Text)
		}
	}
	raw := strings.TrimSpace(text.String())
	if raw == "" {
		return AssessmentResult{}, meta, fmt.Errorf("empty model response")
	}

	var result AssessmentResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return AssessmentResult{}, meta, fmt.Errorf("%w: parse: %v", ErrBadOutput, err)
	}
	if err := result.Validate(); err != nil {
		return AssessmentResult{}, meta, fmt.Errorf("%w: %v", ErrBadOutput, err)
	}
	return result, meta, nil
}
