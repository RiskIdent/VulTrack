package oidc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"

	"github.com/vultrack/vultrack/internal/config"
)

const (
	stateLength   = 32
	stateValidity = 10 * time.Minute
)

// Provider wraps OIDC discovery, OAuth2 config, and ID token verification.
type Provider struct {
	config   *oauth2.Config
	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider

	stateStore *stateStore
}

type stateStore struct {
	mu    sync.Mutex
	items map[string]time.Time
}

func newStateStore() *stateStore {
	s := &stateStore{items: make(map[string]time.Time)}
	go s.cleanup()
	return s
}

func (s *stateStore) add(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[state] = time.Now().Add(stateValidity)
}

func (s *stateStore) validateAndConsume(state string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.items[state]
	if !ok {
		return false
	}
	delete(s.items, state)
	return time.Now().Before(exp)
}

func (s *stateStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for k, exp := range s.items {
			if now.After(exp) {
				delete(s.items, k)
			}
		}
		s.mu.Unlock()
	}
}

// NewProvider creates an OIDC provider from config. The context is used for discovery only.
func NewProvider(ctx context.Context, cfg *config.Config) (*Provider, error) {
	if !cfg.OIDCEnabled || cfg.OIDCIssuer == "" {
		return nil, nil
	}

	provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuer)
	if err != nil {
		return nil, err
	}

	scopes := parseScopes(cfg.OIDCScopes)
	oauth2Config := &oauth2.Config{
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.OIDCRedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.OIDCClientID})

	return &Provider{
		config:     oauth2Config,
		verifier:   verifier,
		provider:   provider,
		stateStore: newStateStore(),
	}, nil
}

func parseScopes(s string) []string {
	if s == "" {
		return []string{oidc.ScopeOpenID, "profile", "email"}
	}
	var out []string
	seen := make(map[string]bool)
	// simple split by space
	for _, v := range splitSpace(s) {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return []string{oidc.ScopeOpenID, "profile", "email"}
	}
	// ensure openid is present
	hasOpenID := false
	for _, v := range out {
		if v == oidc.ScopeOpenID {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		out = append([]string{oidc.ScopeOpenID}, out...)
	}
	return out
}

func splitSpace(s string) []string {
	var parts []string
	var cur []rune
	for _, r := range s {
		if r == ' ' || r == ',' || r == '\t' {
			if len(cur) > 0 {
				parts = append(parts, string(cur))
				cur = nil
			}
		} else {
			cur = append(cur, r)
		}
	}
	if len(cur) > 0 {
		parts = append(parts, string(cur))
	}
	return parts
}

// AuthCodeURL returns the URL to redirect the user to for login. state must be stored and validated on callback.
func (p *Provider) AuthCodeURL(state string) string {
	return p.config.AuthCodeURL(state)
}

// NewState generates a new state value and stores it. Returns the state string for use in AuthCodeURL.
func (p *Provider) NewState() (string, error) {
	b := make([]byte, stateLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	state := hex.EncodeToString(b)
	p.stateStore.add(state)
	return state, nil
}

// ValidateState checks the state and consumes it (one-time use). Returns true if valid.
func (p *Provider) ValidateState(state string) bool {
	return p.stateStore.validateAndConsume(state)
}

// Claims holds the OIDC claims we use for user identity.
type Claims struct {
	Sub               string `json:"sub"`
	Issuer            string `json:"iss"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
}

// ExchangeCode exchanges the authorization code for tokens and verifies the ID token. Returns claims or error.
func (p *Provider) ExchangeCode(ctx context.Context, code string) (*Claims, error) {
	oauth2Token, err := p.config.Exchange(ctx, code)
	if err != nil {
		log.Debug().Err(err).Msg("OAuth2 token exchange failed")
		return nil, err
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, nil
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Debug().Err(err).Msg("ID token verification failed")
		return nil, err
	}

	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	return &claims, nil
}
