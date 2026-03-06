package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const jwtIssuer = "vultrack"

// JWTClaims represents the claims in a VulTrack agent access token (HS256 JWT)
type JWTClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`      // agent ID as decimal string
	Hostname  string `json:"hostname"` // for informational purposes / logging
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

var jwtHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

// CreateAgentJWT creates a signed HS256 JWT for the given agent.
func CreateAgentJWT(secret []byte, agentID int64, hostname string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := JWTClaims{
		Issuer:    jwtIssuer,
		Subject:   fmt.Sprintf("%d", agentID),
		Hostname:  hostname,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWT claims: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	body := jwtHeader + "." + payload
	sig := signHS256(secret, body)
	return body + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ValidateAgentJWT validates the signature and expiry of a JWT, returning the parsed claims.
func ValidateAgentJWT(secret []byte, token string) (*JWTClaims, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}

	body := parts[0] + "." + parts[1]
	expectedSig := signHS256(secret, body)
	providedSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid JWT signature encoding")
	}
	if !hmac.Equal(providedSig, expectedSig) {
		return nil, errors.New("invalid JWT signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid JWT payload encoding")
	}

	var claims JWTClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, errors.New("invalid JWT claims")
	}

	if claims.Issuer != jwtIssuer {
		return nil, errors.New("invalid JWT issuer")
	}
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, errors.New("JWT expired")
	}

	return &claims, nil
}

func signHS256(secret []byte, data string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}
