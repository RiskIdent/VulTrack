package ai

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
)

// capture points the client at a stub server (via ANTHROPIC_BASE_URL, which
// NewClient honors) and returns the headers of the request it made.
func capture(t *testing.T, workspaceID string) http.Header {
	t.Helper()
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"m",` +
			`"content":[{"type":"text","text":"{}"}],"stop_reason":"end_turn",` +
			`"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer srv.Close()

	t.Setenv("ANTHROPIC_BASE_URL", srv.URL)
	c := New("sk-test", workspaceID, 10)
	_, _, _ = c.Assess(context.Background(), AssessmentInput{CVEID: "CVE-2025-1"}, AssessOptions{Model: "m"})
	return got
}

func TestWorkspaceHeader(t *testing.T) {
	if got := capture(t, "wrkspc_123").Get("anthropic-workspace-id"); got != "wrkspc_123" {
		t.Errorf("with workspace id: got %q, want %q", got, "wrkspc_123")
	}
	if h := capture(t, ""); len(h.Values("anthropic-workspace-id")) != 0 {
		t.Errorf("without workspace id: header must be absent, got %q", h.Get("anthropic-workspace-id"))
	}
}

// assessStatus points the client at a stub server returning the given status
// and returns the error Assess produced.
func assessStatus(t *testing.T, status int) error {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"invalid_request_error","message":"boom"}}`))
	}))
	defer srv.Close()

	t.Setenv("ANTHROPIC_BASE_URL", srv.URL)
	c := New("sk-test", "", 10)
	_, _, err := c.Assess(context.Background(), AssessmentInput{CVEID: "CVE-2025-1"}, AssessOptions{Model: "m"})
	if err == nil {
		t.Fatalf("status %d: expected an error", status)
	}
	return err
}

// A 400 is what an identity-linked key without a workspace id produces. It must
// not consume retries: the same request will fail the same way every time.
func TestIsTerminal_BadRequestFromAPI(t *testing.T) {
	err := assessStatus(t, http.StatusBadRequest)

	// Assess wraps the SDK error, so IsTerminal only sees the 400 if errors.As
	// reaches through the wrapping. Assert that explicitly.
	var apiErr *anthropic.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected an *anthropic.Error in the chain, got %T", err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", apiErr.StatusCode)
	}
	if !IsTerminal(err) {
		t.Error("400 must be terminal, got retryable")
	}
}

func TestIsTerminal_StatusCodes(t *testing.T) {
	cases := []struct {
		status   int
		terminal bool
	}{
		{http.StatusBadRequest, true},            // 400 bad request / missing workspace id
		{http.StatusUnauthorized, true},          // 401 rejected key
		{http.StatusForbidden, true},             // 403 no permission
		{http.StatusNotFound, true},              // 404 unknown model
		{http.StatusRequestEntityTooLarge, true}, // 413 request too large
		{http.StatusRequestTimeout, false},       // 408 clears on its own
		{http.StatusConflict, false},             // 409 clears on its own
		{http.StatusTooManyRequests, false},      // 429 rate limited
		{http.StatusInternalServerError, false},
		{http.StatusBadGateway, false},
		{529, false}, // overloaded
	}
	for _, tc := range cases {
		err := fmt.Errorf("anthropic request: %w", &anthropic.Error{StatusCode: tc.status})
		if got := IsTerminal(err); got != tc.terminal {
			t.Errorf("status %d: IsTerminal = %v, want %v", tc.status, got, tc.terminal)
		}
	}
}

func TestIsTerminal_NonAPIErrors(t *testing.T) {
	for _, err := range []error{ErrRefusal, ErrIncompleteOutput, ErrBadOutput, ErrContextTooLarge} {
		if !IsTerminal(fmt.Errorf("wrapped: %w", err)) {
			t.Errorf("%v must be terminal", err)
		}
	}
	// Network failures and timeouts carry no *anthropic.Error and stay retryable.
	for _, err := range []error{errors.New("dial tcp: connection refused"), context.DeadlineExceeded} {
		if IsTerminal(err) {
			t.Errorf("%v must be retryable", err)
		}
	}
}

// The API reports an oversized prompt as a stop reason on a 200, not as an
// error status. Retrying sends the identical prompt, so it must be terminal.
func TestAssess_ContextWindowExceeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"m",` +
			`"content":[],"stop_reason":"model_context_window_exceeded",` +
			`"usage":{"input_tokens":900000,"output_tokens":0}}`))
	}))
	defer srv.Close()

	t.Setenv("ANTHROPIC_BASE_URL", srv.URL)
	c := New("sk-test", "", 10)
	_, meta, err := c.Assess(context.Background(), AssessmentInput{CVEID: "CVE-2025-1"}, AssessOptions{Model: "m"})

	if !errors.Is(err, ErrContextTooLarge) {
		t.Fatalf("got %v, want ErrContextTooLarge", err)
	}
	if !IsTerminal(err) {
		t.Error("an oversized prompt must be terminal")
	}
	// Provenance is still recorded so the failed row shows what it cost.
	if meta.InputTokens != 900000 {
		t.Errorf("got %d input tokens, want 900000", meta.InputTokens)
	}
}
