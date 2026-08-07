package auth

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateAPIKey_ReturnsNonEmptyValues(t *testing.T) {
	key, hash, displayPrefix, err := GenerateAPIKey("tsm")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if key == "" || hash == "" || displayPrefix == "" {
		t.Errorf("expected non-empty values, got key=%q hash=%q prefix=%q", key, hash, displayPrefix)
	}
}

func TestGenerateAPIKey_KeyHasExpectedPrefix(t *testing.T) {
	key, _, _, err := GenerateAPIKey("tsm")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if !strings.HasPrefix(key, "tsm_") {
		t.Errorf("expected key to start with %q, got %q", "tsm_", key)
	}
}

func TestGenerateAPIKey_DisplayPrefixLength(t *testing.T) {
	key, _, displayPrefix, err := GenerateAPIKey("tsm")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if len(displayPrefix) != DisplayPrefixLength {
		t.Errorf("expected display prefix length %d, got %d", DisplayPrefixLength, len(displayPrefix))
	}
	if displayPrefix != key[:DisplayPrefixLength] {
		t.Errorf("display prefix %q is not the leading slice of key %q", displayPrefix, key)
	}
}

func TestGenerateAPIKey_DifferentKeysEachCall(t *testing.T) {
	key1, _, _, err1 := GenerateAPIKey("tsm")
	key2, _, _, err2 := GenerateAPIKey("tsm")
	if err1 != nil || err2 != nil {
		t.Fatalf("GenerateAPIKey errors: %v %v", err1, err2)
	}
	if key1 == key2 {
		t.Error("expected different keys on each call")
	}
}

func TestValidateAPIKey_CorrectKey(t *testing.T) {
	key, hash, _, err := GenerateAPIKey("tsm")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if !ValidateAPIKey(key, hash) {
		t.Error("expected the generated key to validate against its hash")
	}
}

func TestValidateAPIKey_WrongKey(t *testing.T) {
	_, hash, _, err := GenerateAPIKey("tsm")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if ValidateAPIKey("tsm_wrongkey", hash) {
		t.Error("expected a wrong key to fail validation")
	}
}

func TestValidateAPIKey_EmptyKey(t *testing.T) {
	_, hash, _, err := GenerateAPIKey("tsm")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if ValidateAPIKey("", hash) {
		t.Error("expected an empty key to fail validation")
	}
}

// TestMaxAPIKeyPrefixLength_KeepsRandomPartIntact asserts, by construction,
// that MaxAPIKeyPrefixLength keeps fullKey's fixed portion ("<prefix>_")
// plus the 43-byte base64url-encoded random part safely under bcrypt's
// 72-byte input limit. This is the arithmetic invariant the whole fix rests
// on: it doesn't need to trigger real bcrypt truncation to prove that the
// cap prevents it.
func TestMaxAPIKeyPrefixLength_KeepsRandomPartIntact(t *testing.T) {
	const bcryptMaxInputBytes = 72
	randomPartLen := base64.RawURLEncoding.EncodedLen(APIKeyLength) // 43 for 32 random bytes

	maxFullKeyLen := MaxAPIKeyPrefixLength + len("_") + randomPartLen
	if maxFullKeyLen >= bcryptMaxInputBytes {
		t.Fatalf("MaxAPIKeyPrefixLength (%d) allows a fullKey of %d bytes, which is not safely under bcrypt's %d-byte limit",
			MaxAPIKeyPrefixLength, maxFullKeyLen, bcryptMaxInputBytes)
	}
}

func TestGenerateAPIKey_PrefixAtMaxLength_Succeeds(t *testing.T) {
	prefix := strings.Repeat("p", MaxAPIKeyPrefixLength)
	key, hash, _, err := GenerateAPIKey(prefix)
	if err != nil {
		t.Fatalf("expected a prefix of exactly MaxAPIKeyPrefixLength to succeed, got error: %v", err)
	}
	if !strings.HasPrefix(key, prefix+"_") {
		t.Errorf("expected key to start with %q, got %q", prefix+"_", key)
	}
	if !ValidateAPIKey(key, hash) {
		t.Error("expected the generated key to validate against its hash")
	}
}

func TestGenerateAPIKey_PrefixOverMaxLength_Fails(t *testing.T) {
	prefix := strings.Repeat("p", MaxAPIKeyPrefixLength+1)
	key, hash, displayPrefix, err := GenerateAPIKey(prefix)
	if err == nil {
		t.Fatal("expected an error for a prefix one byte over MaxAPIKeyPrefixLength, got nil")
	}
	if key != "" || hash != "" || displayPrefix != "" {
		t.Errorf("expected empty return values on error, got key=%q hash=%q prefix=%q", key, hash, displayPrefix)
	}
}

func TestGenerateAPIKey_CustomPrefix(t *testing.T) {
	key, hash, _, err := GenerateAPIKey("myapp")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if !strings.HasPrefix(key, "myapp_") {
		t.Errorf("expected key to start with %q, got %q", "myapp_", key)
	}
	if !ValidateAPIKey(key, hash) {
		t.Error("expected custom-prefix key to validate")
	}
}

func TestExtractAPIKeyFromHeader_ValidBearer(t *testing.T) {
	key, err := ExtractAPIKeyFromHeader("Bearer tsm_abc123xyz")
	if err != nil {
		t.Fatalf("ExtractAPIKeyFromHeader: %v", err)
	}
	if key != "tsm_abc123xyz" {
		t.Errorf("expected %q, got %q", "tsm_abc123xyz", key)
	}
}

func TestExtractAPIKeyFromHeader_EmptyHeader(t *testing.T) {
	if _, err := ExtractAPIKeyFromHeader(""); err == nil {
		t.Error("expected an error for an empty header")
	}
}

func TestExtractAPIKeyFromHeader_MissingBearerPrefix(t *testing.T) {
	if _, err := ExtractAPIKeyFromHeader("tsm_abc123xyz"); err == nil {
		t.Error("expected an error when the Bearer prefix is missing")
	}
}

func TestExtractAPIKeyFromHeader_BearerWithNoKey(t *testing.T) {
	if _, err := ExtractAPIKeyFromHeader("Bearer "); err == nil {
		t.Error("expected an error when no key follows Bearer")
	}
}

func TestExtractAPIKeyFromHeader_BearerWithWhitespaceOnly(t *testing.T) {
	if _, err := ExtractAPIKeyFromHeader("Bearer    "); err == nil {
		t.Error("expected an error when only whitespace follows Bearer")
	}
}

// TestExtractAPIKeyFromHeader_SchemeIsCaseInsensitive covers RFC 7235 §2.1
// (auth-scheme is a case-insensitive token) and RFC 6750 §2.1, which repeats it
// for Bearer. The previous strings.HasPrefix(header, "Bearer ") accepted exactly
// one capitalisation and exactly one separator, so a conformant client sending
// "bearer <key>" was told its header "must start with 'Bearer '" — while in fact
// sending Bearer. This fails CLOSED (a conformant caller is denied, never
// wrongly admitted), which is why it is an interoperability fix; both suite
// backends route every API-key request through this one parser, so the
// deviation was uniform across the suite.
func TestExtractAPIKeyFromHeader_SchemeIsCaseInsensitive(t *testing.T) {
	for _, header := range []string{
		"Bearer tsm_abc123xyz",
		"bearer tsm_abc123xyz",
		"BEARER tsm_abc123xyz",
		"BeArEr tsm_abc123xyz",
		"Bearer\ttsm_abc123xyz", // HTAB is valid RFC 7230 whitespace
		"Bearer   tsm_abc123xyz",
	} {
		key, err := ExtractAPIKeyFromHeader(header)
		if err != nil {
			t.Errorf("ExtractAPIKeyFromHeader(%q): %v", header, err)
			continue
		}
		if key != "tsm_abc123xyz" {
			t.Errorf("ExtractAPIKeyFromHeader(%q) = %q, want %q", header, key, "tsm_abc123xyz")
		}
	}
}

// TestExtractAPIKeyFromHeader_CredentialIsNotCaseFolded is the paired
// direction: only the SCHEME token is case-insensitive. Folding the credential
// too would collapse distinct keys onto one another.
func TestExtractAPIKeyFromHeader_CredentialIsNotCaseFolded(t *testing.T) {
	key, err := ExtractAPIKeyFromHeader("bearer TsM_AbC123XyZ")
	if err != nil {
		t.Fatalf("ExtractAPIKeyFromHeader: %v", err)
	}
	if key != "TsM_AbC123XyZ" {
		t.Errorf("credential = %q, want it preserved verbatim", key)
	}
}

// TestExtractAPIKeyFromHeader_RejectsOtherSchemes keeps the relaxation from
// becoming "accept anything with a space in it".
func TestExtractAPIKeyFromHeader_RejectsOtherSchemes(t *testing.T) {
	for _, header := range []string{
		"Basic dXNlcjpwYXNz",
		"Token tsm_abc123xyz",
		"Bearerish tsm_abc123xyz",
		"Bear tsm_abc123xyz",
		"tsm_abc123xyz",
	} {
		if _, err := ExtractAPIKeyFromHeader(header); err == nil {
			t.Errorf("ExtractAPIKeyFromHeader(%q) succeeded; want a rejection", header)
		}
	}
}
