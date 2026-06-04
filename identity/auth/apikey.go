package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	// APIKeyLength is the length of the random part of the API key in bytes.
	APIKeyLength = 32

	// DisplayPrefixLength is the number of leading characters shown in displays
	// and used as the lookup prefix for stored keys.
	DisplayPrefixLength = 10

	// BcryptCost is the cost factor for bcrypt hashing of API keys.
	BcryptCost = 12
)

// GenerateAPIKey creates a new random API key with the given prefix.
// It returns the full key (to show the caller once), the bcrypt hash (to
// store), and the display prefix (safe to persist for identification).
func GenerateAPIKey(prefix string) (key string, hash string, displayPrefix string, err error) {
	randomBytes := make([]byte, APIKeyLength)
	if _, err = rand.Read(randomBytes); err != nil {
		return "", "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	randomPart := base64.RawURLEncoding.EncodeToString(randomBytes)
	fullKey := fmt.Sprintf("%s_%s", prefix, randomPart)

	hashBytes, err := bcrypt.GenerateFromPassword([]byte(fullKey), BcryptCost)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to hash API key: %w", err)
	}

	displayPrefixStr := fullKey
	if len(fullKey) > DisplayPrefixLength {
		displayPrefixStr = fullKey[:DisplayPrefixLength]
	}

	return fullKey, string(hashBytes), displayPrefixStr, nil
}

// ValidateAPIKey reports whether a provided key matches the stored bcrypt hash.
func ValidateAPIKey(providedKey, storedHash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(providedKey)) == nil
}

// ExtractAPIKeyFromHeader extracts the API key from an Authorization header.
// Expected format: "Bearer <key>".
func ExtractAPIKeyFromHeader(header string) (string, error) {
	if header == "" {
		return "", errors.New("authorization header is empty")
	}

	if !strings.HasPrefix(header, "Bearer ") {
		return "", errors.New("authorization header must start with 'Bearer '")
	}

	key := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if key == "" {
		return "", errors.New("API key is empty after Bearer prefix")
	}

	return key, nil
}
