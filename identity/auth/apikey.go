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

	// MinPrefixRandomChars is how many characters of the RANDOM part of a key
	// are guaranteed to survive into the persisted key_prefix.
	//
	// key_prefix is not decoration. It is the sole narrowing predicate of the
	// authentication lookup (store.APIKeyRepository.GetAPIKeysByPrefix,
	// `WHERE key_prefix = $1`), and every row it returns costs the
	// authenticating host one bcrypt comparison at BcryptCost — roughly a
	// quarter-second each. Whatever entropy lives in this window is therefore
	// the only thing dividing the key table into buckets, and the only thing
	// bounding how much work an unauthenticated request can conscript.
	//
	// The prefix is deliberately NOT secret — it is shown in UIs so an
	// operator can identify a key — so an attacker holding no valid key at
	// all can present it and trigger whatever fan-out it selects. Two
	// characters of base64url alphabet is 64^2 = 4096 buckets, which bounds
	// that fan-out to (live keys / 4096) in expectation.
	MinPrefixRandomChars = 2

	// MaxAPIKeyPrefixLength is the maximum allowed length, in bytes, of the
	// caller-supplied prefix passed to GenerateAPIKey.
	//
	// TWO independent limits bear on this value. The cap is the tighter of
	// them, and the pair is enforced mechanically below rather than left to
	// whoever edits these constants next.
	//
	// 1. bcrypt's input window (the limit this constant was introduced for).
	// bcrypt only hashes the first 72 bytes of its input, and GenerateAPIKey
	// builds fullKey as "<prefix>_<randomPart>" — the random, unpredictable
	// part is at the END of the string. If the fixed prefix portion
	// ("<prefix>_") grows too large, it starts pushing bytes of randomPart out
	// of bcrypt's 72-byte window, silently truncating the entropy that makes
	// each key unique; at prefix lengths >= 72 the random part is truncated
	// away entirely, so bcrypt hashes an identical input for every key sharing
	// that prefix (any such key would then validate against any other's stored
	// hash). randomPart is a fixed 43-byte base64url encoding of APIKeyLength
	// (32) random bytes, so this limit alone would permit 20 bytes: fullKey
	// tops out at 21+43 = 64 bytes, under 72 with headroom.
	//
	// 2. The lookup discriminator, which is STRICTER and is why the cap is 7.
	// displayPrefix is fullKey's first DisplayPrefixLength (10) bytes, so the
	// fixed portion "<prefix>_" and the random part SHARE that 10-byte window.
	// At a 9-byte prefix the fixed portion fills it exactly and key_prefix
	// contains zero random characters — byte-identical for every key the
	// application ever issues, collapsing GetAPIKeysByPrefix into a
	// full-table scan and one bcrypt per live key, for any unauthenticated
	// caller who presents the application's public prefix. Between 8 and 9
	// bytes the discriminator is not gone but is far too weak to bound
	// anything (a single character, 64 buckets).
	//
	// A 7-byte cap leaves at least MinPrefixRandomChars characters of
	// randomPart inside the window for every prefix this function accepts.
	// Both shipped consumers use 3-byte prefixes ("tfr", "tsm") and are
	// unaffected.
	MaxAPIKeyPrefixLength = 7
)

// Enforce, AT COMPILE TIME, that the caller-supplied prefix cap actually
// leaves MinPrefixRandomChars characters of randomPart inside the
// DisplayPrefixLength-byte lookup window:
//
//	len("<prefix>_") + MinPrefixRandomChars <= DisplayPrefixLength
//
// This relationship is the whole content of the fix for the collapse described
// on MaxAPIKeyPrefixLength, and it is a relationship BETWEEN three constants
// that live next to each other and look independently adjustable. It was
// already violated once, silently, by a change that reasoned carefully about
// bcrypt's 72-byte window and never noticed the 10-byte one.
//
// A conversion of an untyped constant expression to uint is a compile-time
// error when the value is negative, so raising MaxAPIKeyPrefixLength (or
// lowering DisplayPrefixLength, or raising MinPrefixRandomChars) past the
// point where the guarantee holds fails the BUILD, in this file, rather than
// silently weakening authentication. A doc comment asking the next editor to
// remember this would be the weakest available control; this one cannot be
// skipped, and does not depend on a test being run.
const _ = uint(DisplayPrefixLength - (MaxAPIKeyPrefixLength + 1) - MinPrefixRandomChars)

// GenerateAPIKey creates a new random API key with the given prefix.
// It returns the full key (to show the caller once), the bcrypt hash (to
// store), and the display prefix (safe to persist for identification).
//
// The returned displayPrefix is what a host persists as api_keys.key_prefix
// and what the authentication path looks keys up by, so it is a lookup
// DISCRIMINATOR as much as a label. prefix must be at most
// MaxAPIKeyPrefixLength bytes; longer prefixes are rejected before any random
// bytes are generated, because they both push randomPart out of bcrypt's
// 72-byte input window and crowd it out of the DisplayPrefixLength-byte
// lookup window. See MaxAPIKeyPrefixLength for both limits.
func GenerateAPIKey(prefix string) (key string, hash string, displayPrefix string, err error) {
	if len(prefix) > MaxAPIKeyPrefixLength {
		return "", "", "", fmt.Errorf("api key prefix %q is %d bytes, exceeds MaxAPIKeyPrefixLength (%d); a longer prefix crowds the random part out of the %d-byte key_prefix lookup window, leaving fewer than %d random characters to discriminate one key from another", prefix, len(prefix), MaxAPIKeyPrefixLength, DisplayPrefixLength, MinPrefixRandomChars)
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
//
// The auth-scheme is matched case-INSENSITIVELY, per RFC 7235 §2.1 ("the
// auth-scheme is a case-insensitive token") and RFC 6750 §2.1, which repeats
// that rule for Bearer specifically. The separator may be any run of RFC 7230
// whitespace (SP or HTAB), not only a single space. A previous
// strings.HasPrefix(header, "Bearer ") accepted exactly one capitalisation and
// exactly one separator, so a conformant client sending "bearer <key>" or
// "Bearer\t<key>" was rejected with the confusing message "must start with
// 'Bearer '" — while in fact sending Bearer.
//
// The CREDENTIAL is not case-folded: only the scheme token is. Both suite
// backends route every API-key request through this one parser, so the
// deviation was uniform across the suite; it failed CLOSED (a conformant caller
// was denied, never wrongly admitted), which is why this is an
// interoperability fix and not an authentication fix.
func ExtractAPIKeyFromHeader(header string) (string, error) {
	if header == "" {
		return "", errors.New("authorization header is empty")
	}

	// Split on the FIRST run of RFC 7230 whitespace: everything before it is the
	// auth-scheme, everything after is the credential.
	trimmed := strings.TrimLeft(header, " \t")
	sep := strings.IndexAny(trimmed, " \t")
	if sep < 0 || !strings.EqualFold(trimmed[:sep], "Bearer") {
		return "", errors.New("authorization header must start with 'Bearer '")
	}

	key := strings.TrimSpace(trimmed[sep+1:])
	if key == "" {
		return "", errors.New("API key is empty after Bearer prefix")
	}

	return key, nil
}
