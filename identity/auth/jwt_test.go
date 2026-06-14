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

func TestTokenManager_GeneratesUniqueJTI(t *testing.T) {
	tm := newTM()
	tok1, _ := tm.Generate("u", "e", nil, time.Hour)
	tok2, _ := tm.Generate("u", "e", nil, time.Hour)
	c1, err := tm.Validate(tok1)
	if err != nil {
		t.Fatalf("Validate tok1: %v", err)
	}
	c2, err := tm.Validate(tok2)
	if err != nil {
		t.Fatalf("Validate tok2: %v", err)
	}
	if c1.JTI == "" || c2.JTI == "" {
		t.Fatal("expected non-empty JTI on both tokens")
	}
	if c1.JTI == c2.JTI {
		t.Errorf("expected unique JTIs, got %q twice", c1.JTI)
	}
}

func TestTokenManager_AllowedIssuers(t *testing.T) {
	tm := newTM() // issuer "test-issuer"
	tok, err := tm.Generate("u", "e", nil, time.Hour)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Default (unset) accepts any issuer — backward compatible.
	if _, err := tm.Validate(tok); err != nil {
		t.Fatalf("default (no pin) should accept: %v", err)
	}

	// Pin to a set that INCLUDES the token's issuer → accepted.
	tm.SetAllowedIssuers([]string{"test-issuer", "terraform-registry"})
	if _, err := tm.Validate(tok); err != nil {
		t.Errorf("issuer in allowed set should validate: %v", err)
	}

	// Pin to a set that EXCLUDES the token's issuer → rejected.
	tm.SetAllowedIssuers([]string{"some-other-app"})
	if _, err := tm.Validate(tok); err == nil {
		t.Error("issuer not in allowed set should be rejected")
	}

	// Clearing the set restores accept-any (default behaviour).
	tm.SetAllowedIssuers(nil)
	if _, err := tm.Validate(tok); err != nil {
		t.Errorf("cleared allowed set should accept any issuer: %v", err)
	}
}

func TestTokenManager_AllowedIssuers_AcrossSecretRotation(t *testing.T) {
	// The pin is enforced in validateWith, so it also rejects a disallowed issuer
	// on the previous-secret (rotation-overlap) path.
	tm := newTM()
	oldTok, err := tm.Generate("u", "e", nil, time.Hour)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	tm.RotateSecret([]byte("a-new-rotated-secret-32-bytes-minimum!"))
	tm.SetAllowedIssuers([]string{"some-other-app"}) // excludes "test-issuer"
	if _, err := tm.Validate(oldTok); err == nil {
		t.Error("old (previous-secret) token with a disallowed issuer must be rejected")
	}
}

func TestTokenManager_RotateSecret_OverlapThenClear(t *testing.T) {
	tm := newTM()
	// Token signed with the original secret.
	oldTok, err := tm.Generate("u", "e", nil, time.Hour)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Rotate to a new secret. The old token must still validate (overlap).
	tm.RotateSecret([]byte("a-new-rotated-secret-32-bytes-minimum!"))
	if _, err := tm.Validate(oldTok); err != nil {
		t.Errorf("old token should still validate during overlap: %v", err)
	}

	// A freshly generated token uses the new secret and validates.
	newTok, err := tm.Generate("u", "e", nil, time.Hour)
	if err != nil {
		t.Fatalf("Generate after rotate: %v", err)
	}
	if _, err := tm.Validate(newTok); err != nil {
		t.Errorf("new token should validate with rotated secret: %v", err)
	}

	// Ending the overlap invalidates tokens signed with the previous secret.
	tm.ClearPreviousSecret()
	if _, err := tm.Validate(oldTok); err == nil {
		t.Error("old token should fail after the previous secret is cleared")
	}
	if _, err := tm.Validate(newTok); err != nil {
		t.Errorf("new token should still validate after clearing previous: %v", err)
	}
}
