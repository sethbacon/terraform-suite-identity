package auth

import (
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
