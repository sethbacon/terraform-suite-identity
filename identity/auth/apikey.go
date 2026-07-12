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

	// MaxAPIKeyPrefixLength is the maximum allowed length, in bytes, of the
	// caller-supplied prefix passed to GenerateAPIKey.
	//
	// bcrypt only hashes the first 72 bytes of its input, and
	// GenerateAPIKey builds fullKey as "<prefix>_<randomPart>" — the random,
	// unpredictable part is at the END of the string. If the fixed prefix
	// portion ("<prefix>_") grows too large, it starts pushing bytes of
	// randomPart out of bcrypt's 72-byte window, silently truncating the
	// entropy that makes each key unique; at prefix lengths >= 72 the random
	// part is truncated away entirely, so bcrypt hashes an identical input
	// for every key sharing that prefix (any such key would then validate
	// against any other's stored hash).
	//
	// randomPart is a fixed 43-byte base64url encoding of APIKeyLength (32)
	// random bytes. Capping the prefix at 20 bytes keeps the fixed portion
	// ("<prefix>_") to at most 21 bytes, so fullKey's total length tops out
	// at 21+43 = 64 bytes — safely under bcrypt's 72-byte limit with 8 bytes
	// of headroom — meaning the full random part is always hashed intact for
	// any caller respecting this cap.
	MaxAPIKeyPrefixLength = 20
)

// GenerateAPIKey creates a new random API key with the given prefix.
// It returns the full key (to show the caller once), the bcrypt hash (to
// store), and the display prefix (safe to persist for identification).
//
// prefix must be at most MaxAPIKeyPrefixLength bytes; longer prefixes are
// rejected before any random bytes are generated, to avoid bcrypt's 72-byte
// input truncation silently weakening (or, for sufficiently long prefixes,
// completely eliminating) the key's random entropy.
func GenerateAPIKey(prefix string) (key string, hash string, displayPrefix string, err error) {
	if len(prefix) > MaxAPIKeyPrefixLength {
		return "", "", "", fmt.Errorf("api key prefix %q is %d bytes, exceeds MaxAPIKeyPrefixLength (%d)", prefix, len(prefix), MaxAPIKeyPrefixLength)
	}

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
