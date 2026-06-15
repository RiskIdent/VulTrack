package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const (
	// EnrollmentKeyPrefix is the prefix for enrollment keys
	EnrollmentKeyPrefix = "enroll_"
	// AgentTokenPrefix is the prefix for agent tokens (v1)
	AgentTokenPrefix = "at_"
	// RefreshTokenPrefix is the prefix for v2 refresh tokens
	RefreshTokenPrefix = "rt_"
	// APITokenPrefix is the prefix for API tokens (MCP interface)
	APITokenPrefix = "vt_"
	// KeyLength is the length of the random part of keys (in bytes, will be hex encoded)
	KeyLength = 32
)

// GenerateEnrollmentKey generates a new enrollment key
// Returns the full key (to show once) and the prefix (for identification)
func GenerateEnrollmentKey() (fullKey string, prefix string, err error) {
	randomBytes := make([]byte, KeyLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	randomPart := hex.EncodeToString(randomBytes)
	fullKey = EnrollmentKeyPrefix + randomPart
	// Prefix is just the first 8 chars of the random part (for display)
	prefix = randomPart[:8]

	return fullKey, prefix, nil
}

// GenerateAgentToken generates a new agent token
// Returns the full token (to store on agent) and the prefix (for identification)
func GenerateAgentToken() (fullToken string, prefix string, err error) {
	randomBytes := make([]byte, KeyLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	randomPart := hex.EncodeToString(randomBytes)
	fullToken = AgentTokenPrefix + randomPart
	// Prefix is just the first 8 chars of the random part (for display)
	prefix = randomPart[:8]

	return fullToken, prefix, nil
}

// HashKey creates a SHA-256 hash of a key
func HashKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// ValidateKeyFormat checks if a key has the correct format
func ValidateKeyFormat(key string, expectedPrefix string) bool {
	if len(key) < len(expectedPrefix)+16 {
		return false
	}
	return key[:len(expectedPrefix)] == expectedPrefix
}

// ValidateEnrollmentKey checks if an enrollment key has the correct format
func ValidateEnrollmentKey(key string) bool {
	return ValidateKeyFormat(key, EnrollmentKeyPrefix)
}

// ValidateAgentToken checks if an agent token has the correct format
func ValidateAgentToken(token string) bool {
	return ValidateKeyFormat(token, AgentTokenPrefix)
}

// GetKeyPrefix extracts the prefix from a key (first 8 chars of the random part)
func GetKeyPrefix(key string, typePrefix string) string {
	if len(key) < len(typePrefix)+8 {
		if len(key) > len(typePrefix) {
			return key[len(typePrefix):]
		}
		return ""
	}
	return key[len(typePrefix) : len(typePrefix)+8]
}

// GetEnrollmentKeyPrefix extracts the prefix from an enrollment key
func GetEnrollmentKeyPrefix(key string) string {
	return GetKeyPrefix(key, EnrollmentKeyPrefix)
}

// GetAgentTokenPrefix extracts the prefix from an agent token
func GetAgentTokenPrefix(token string) string {
	return GetKeyPrefix(token, AgentTokenPrefix)
}

// GenerateRefreshToken generates a new v2 refresh token
func GenerateRefreshToken() (fullToken string, prefix string, err error) {
	randomBytes := make([]byte, KeyLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	randomPart := hex.EncodeToString(randomBytes)
	fullToken = RefreshTokenPrefix + randomPart
	prefix = randomPart[:8]
	return fullToken, prefix, nil
}

// ValidateRefreshToken checks if a refresh token has the correct format
func ValidateRefreshToken(token string) bool {
	return ValidateKeyFormat(token, RefreshTokenPrefix)
}

// GenerateAPIToken generates a new API token for the MCP interface.
// Returns the full token (to show once to the user) and the prefix (for identification).
func GenerateAPIToken() (fullToken string, prefix string, err error) {
	randomBytes := make([]byte, KeyLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	randomPart := hex.EncodeToString(randomBytes)
	fullToken = APITokenPrefix + randomPart
	prefix = randomPart[:8]
	return fullToken, prefix, nil
}

// ValidateAPIToken checks if an API token has the correct format
func ValidateAPIToken(token string) bool {
	return ValidateKeyFormat(token, APITokenPrefix)
}
