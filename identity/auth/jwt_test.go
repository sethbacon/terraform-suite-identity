package auth

import (
	"testing"
	"time"
)

func newTM() *TokenManager {
	return NewTokenManager("test-secret-key-that-is-long-enough-32+", "test-issuer")
}

func TestTokenManager_GenerateValidateRoundTrip(t *testing.T) {
	tm := newTM()
	scopes := []string{"analysis:read", "admin"}
	tok, err := tm.Generate("user-1", "u@example.com", scopes, time.Hour)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	claims, err := tm.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.UserID != "user-1" || claims.Email != "u@example.com" {
		t.Errorf("claims mismatch: %+v", claims)
	}
	if len(claims.Scopes) != 2 || claims.Scopes[0] != "analysis:read" {
		t.Errorf("scopes mismatch: %v", claims.Scopes)
	}
	if claims.Issuer != "test-issuer" || claims.Subject != "user-1" {
		t.Errorf("registered claims mismatch: issuer=%q subject=%q", claims.Issuer, claims.Subject)
	}
}

func TestTokenManager_RejectsWrongSecret(t *testing.T) {
	tok, err := newTM().Generate("u", "e", nil, time.Hour)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	other := NewTokenManager("a-completely-different-secret-value-xx", "test-issuer")
	if _, err := other.Validate(tok); err == nil {
		t.Error("expected validation to fail with a different secret")
	}
}

func TestTokenManager_RejectsExpiredToken(t *testing.T) {
	tm := newTM()
	tok, err := tm.Generate("u", "e", nil, -time.Minute) // already expired
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := tm.Validate(tok); err == nil {
		t.Error("expected validation to fail for an expired token")
	}
}

func TestTokenManager_RejectsTamperedToken(t *testing.T) {
	tm := newTM()
	tok, err := tm.Generate("u", "e", nil, time.Hour)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := tm.Validate(tok + "x"); err == nil {
		t.Error("expected validation to fail for a tampered token")
	}
}

func TestTokenManager_DefaultExpiry(t *testing.T) {
	tm := newTM()
	tok, err := tm.Generate("u", "e", nil, 0) // 0 → DefaultExpiry
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	claims, err := tm.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	d := time.Until(claims.ExpiresAt.Time)
	if d <= 0 || d > DefaultExpiry+time.Minute {
		t.Errorf("expected ~DefaultExpiry, got %s", d)
	}
}
