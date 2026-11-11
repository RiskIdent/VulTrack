package config

import "testing"

func TestBaseURL(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"explicit", Config{PublicURL: "https://vt.example.com/", OIDCFrontendURL: "https://other"}, "https://vt.example.com"},
		{"frontend url", Config{OIDCFrontendURL: "https://vt.example.com/"}, "https://vt.example.com"},
		{"relative frontend url, redirect url", Config{OIDCFrontendURL: "/", OIDCRedirectURL: "https://vt.example.com:8443/api/v1/auth/callback"}, "https://vt.example.com:8443"},
		{"nothing", Config{OIDCFrontendURL: "/"}, ""},
	}
	for _, c := range cases {
		if got := c.cfg.BaseURL(); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
