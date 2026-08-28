// Package ai wraps the Anthropic API to produce advisory CVE assessments.
// It is the only place that talks to the LLM; callers pass CVE facts in and get
// a validated, structured assessment back.
package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	// ErrContextTooLarge means the prompt exceeded the model's context window.
	// Usually the infrastructure context is too long for the configured model.
	ErrContextTooLarge = errors.New("prompt exceeded the model context window")
)

// IsTerminal reports whether err will keep failing for the same input, so the
// caller should record the failure rather than spend retries on it.
//
// Terminal are the model-output errors above plus API errors that reflect a bad
// request or bad configuration — a wrong model id, a rejected key, a missing
// workspace id. Those are 4xx, with three exceptions that do clear on their
// own: 408 (timeout), 409 (conflict) and 429 (rate limit). Everything else
// stays retryable, including 5xx and network failures, which carry no
// [anthropic.Error] at all.
func IsTerminal(err error) bool {
	if errors.Is(err, ErrRefusal) || errors.Is(err, ErrIncompleteOutput) ||
		errors.Is(err, ErrBadOutput) || errors.Is(err, ErrContextTooLarge) {
		return true
	}
	var apiErr *anthropic.Error
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.StatusCode {
	case http.StatusRequestTimeout, http.StatusConflict, http.StatusTooManyRequests:
		return false
	}
	return apiErr.StatusCode >= 400 && apiErr.StatusCode < 500
}

// Client produces CVE assessments via the Anthropic API.
type Client struct {
	api       anthropic.Client
	maxTokens int64
	timeout   time.Duration
}

// New creates an AI client. timeoutSec bounds each request (0 = no extra bound).
//
// workspaceID may be empty for a workspace-scoped API key, where the server
// derives the workspace from the key itself. An identity-linked key is not
// bound to a single workspace, so the server rejects requests that do not name
// one; pass the `wrkspc_*` id in that case. The SDK only derives the header
// from ANTHROPIC_WORKSPACE_ID on its profile and federation credential paths —
// an explicit WithAPIKey short-circuits those, so we set it ourselves.
func New(apiKey, workspaceID string, timeoutSec int) *Client {
	opts := []option.RequestOption{option.WithAPIKey(apiKey)}
	if workspaceID != "" {
		opts = append(opts, option.WithHeader("anthropic-workspace-id", workspaceID))
	}
	return &Client{
		api:       anthropic.NewClient(opts...),
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
	case anthropic.StopReasonModelContextWindowExceeded:
		return AssessmentResult{}, meta, ErrContextTooLarge
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
