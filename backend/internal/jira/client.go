package jira

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/config"
)

// Client talks to the Jira Cloud REST API v3.
type Client struct {
	baseURL    string
	projectKey string
	issueType  string
	authHeader string
	http       *http.Client
	enabled    bool
}

// New creates a Jira client. If Jira is disabled the client is a safe no-op.
func New(cfg *config.Config) *Client {
	c := &Client{
		enabled:    cfg.JiraEnabled,
		baseURL:    strings.TrimRight(cfg.JiraBaseURL, "/"),
		projectKey: cfg.JiraProjectKey,
		issueType:  cfg.JiraIssueType,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	if cfg.JiraEnabled {
		// Jira Cloud: Basic Auth with email:api_token
		creds := cfg.JiraUserEmail + ":" + cfg.JiraAPIToken
		c.authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))

		log.Info().
			Str("baseURL", c.baseURL).
			Str("project", c.projectKey).
			Str("issueType", c.issueType).
			Msg("Jira integration enabled")
	}

	return c
}

// Enabled returns whether the Jira integration is active.
func (c *Client) Enabled() bool {
	return c.enabled
}

// ── Public types ────────────────────────────────────────────────────────────

// CreateIssueRequest holds the data needed to create a Jira issue.
type CreateIssueRequest struct {
	Summary     string
	Description string // plain-text; converted to ADF internally
	Labels      []string
}

// CreateIssueResult is returned after a successful issue creation.
type CreateIssueResult struct {
	Key string // e.g. "SEC-42"
	URL string // browsable link
}

// ── Issue CRUD ──────────────────────────────────────────────────────────────

// CreateIssue creates a new issue and returns its key and URL.
func (c *Client) CreateIssue(ctx context.Context, req CreateIssueRequest) (*CreateIssueResult, error) {
	if !c.enabled {
		return nil, fmt.Errorf("jira integration is disabled")
	}

	// Build ADF (Atlassian Document Format) description
	adfDesc := textToADF(req.Description)

	payload := map[string]interface{}{
		"fields": map[string]interface{}{
			"project": map[string]string{
				"key": c.projectKey,
			},
			"issuetype": map[string]string{
				"name": c.issueType,
			},
			"summary": req.Summary,
			"description": adfDesc,
			"labels": req.Labels,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal issue payload: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", "/rest/api/3/issue", body)
	if err != nil {
		return nil, fmt.Errorf("create issue request: %w", err)
	}

	var result struct {
		Key  string `json:"key"`
		Self string `json:"self"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("parse create issue response: %w", err)
	}

	issueURL := fmt.Sprintf("%s/browse/%s", c.baseURL, result.Key)

	log.Info().
		Str("key", result.Key).
		Str("url", issueURL).
		Msg("Jira issue created")

	return &CreateIssueResult{
		Key: result.Key,
		URL: issueURL,
	}, nil
}


// ── HTTP helper ─────────────────────────────────────────────────────────────

func (c *Client) doRequest(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	url := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", c.authHeader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Try to extract Jira error messages
		var jiraErr struct {
			Errors       map[string]string `json:"errors"`
			ErrorMessages []string          `json:"errorMessages"`
		}
		if json.Unmarshal(respBody, &jiraErr) == nil {
			msgs := jiraErr.ErrorMessages
			for k, v := range jiraErr.Errors {
				msgs = append(msgs, k+": "+v)
			}
			if len(msgs) > 0 {
				return nil, fmt.Errorf("jira API %d: %s", resp.StatusCode, strings.Join(msgs, "; "))
			}
		}
		return nil, fmt.Errorf("jira API %d: %s", resp.StatusCode, string(respBody))
	}

	// Some endpoints (e.g. transitions POST) return 204 No Content
	if resp.StatusCode == http.StatusNoContent {
		return []byte("{}"), nil
	}

	return respBody, nil
}

// ── ADF helper ──────────────────────────────────────────────────────────────

// textToADF converts plain text into Jira Cloud's Atlassian Document Format.
// Each line becomes a paragraph; preserves line breaks naturally.
func textToADF(text string) map[string]interface{} {
	lines := strings.Split(text, "\n")
	content := make([]interface{}, 0, len(lines))

	for _, line := range lines {
		if line == "" {
			// Empty line = empty paragraph (visual separator)
			content = append(content, map[string]interface{}{
				"type":    "paragraph",
				"content": []interface{}{},
			})
			continue
		}

		content = append(content, map[string]interface{}{
			"type": "paragraph",
			"content": []interface{}{
				map[string]interface{}{
					"type": "text",
					"text": line,
				},
			},
		})
	}

	return map[string]interface{}{
		"version": 1,
		"type":    "doc",
		"content": content,
	}
}
