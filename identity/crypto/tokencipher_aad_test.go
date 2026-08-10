package crypto

import (
	"errors"
	"strings"
	"testing"
)

// Issue #153 — Seal passed nil additionalData, so a ciphertext carried no
// binding to the row, column or purpose it belonged to. Anyone with database
// write access could move a sealed value between rows or between fields and GCM
// would authenticate it happily.
//
// SealWithContext/OpenWithContext add that binding. The pair is additive: Seal
// and Open are untouched so ciphertexts already at rest keep opening, and
// ReSealWithContext converts them.

func newTestCipher(t *testing.T) *TokenCipher {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tc, err := NewTokenCipher(key)
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	return tc
}

func TestSealWithContext_RoundTrips(t *testing.T) {
	tc := newTestCipher(t)
	ctx := []byte("notify_channel:chan-1:target")

	sealed, err := tc.SealWithContext("https://hooks.example/abc", ctx)
	if err != nil {
		t.Fatalf("SealWithContext: %v", err)
	}
	got, err := tc.OpenWithContext(sealed, ctx)
	if err != nil {
		t.Fatalf("OpenWithContext: %v", err)
	}
	if got != "https://hooks.example/abc" {
		t.Errorf("round trip = %q", got)
	}
}

// The attack the binding exists to stop: lift a sealed value out of one row and
// write it into another. Without AAD this succeeds and GCM raises nothing.
func TestSealWithContext_CiphertextDoesNotOpenUnderAnotherRowsContext(t *testing.T) {
	tc := newTestCipher(t)
	victim := []byte("notify_channel:chan-1:target")
	attacker := []byte("notify_channel:chan-2:target")

	sealed, err := tc.SealWithContext("https://hooks.example/victim", victim)
	if err != nil {
		t.Fatalf("SealWithContext: %v", err)
	}

	if _, err := tc.OpenWithContext(sealed, attacker); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("a ciphertext moved to another row opened, or failed for the wrong reason: %v", err)
	}
}

// Same value, same key, different slot -> the two ciphertexts are not
// interchangeable. This is the property a per-row context buys over a constant
// one, and a constant context would pass the test above while failing this.
func TestSealWithContext_SameValueInTwoSlotsIsNotInterchangeable(t *testing.T) {
	tc := newTestCipher(t)
	a := []byte("notify_channel:chan-1:target")
	b := []byte("notify_channel:chan-2:target")

	sealedA, err := tc.SealWithContext("same-secret", a)
	if err != nil {
		t.Fatalf("SealWithContext(a): %v", err)
	}
	sealedB, err := tc.SealWithContext("same-secret", b)
	if err != nil {
		t.Fatalf("SealWithContext(b): %v", err)
	}

	if _, err := tc.OpenWithContext(sealedA, b); !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("A's ciphertext opened under B's context: %v", err)
	}
	if _, err := tc.OpenWithContext(sealedB, a); !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("B's ciphertext opened under A's context: %v", err)
	}
}

// No cross-compatibility in either direction. Asserted explicitly because it is
// the reason existing data needs converting rather than just deploying: if these
// interoperated, the binding would not be a binding.
func TestSealAndSealWithContext_DoNotInteroperate(t *testing.T) {
	tc := newTestCipher(t)
	ctx := []byte("notify_channel:chan-1:target")

	legacy, err := tc.Seal("secret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := tc.OpenWithContext(legacy, ctx); !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("a legacy ciphertext opened with a context: %v", err)
	}

	bound, err := tc.SealWithContext("secret", ctx)
	if err != nil {
		t.Fatalf("SealWithContext: %v", err)
	}
	if _, err := tc.Open(bound); !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("a bound ciphertext opened without its context: %v", err)
	}
}

func TestReSealWithContext_ConvertsLegacyCiphertext(t *testing.T) {
	tc := newTestCipher(t)
	ctx := []byte("notify_channel:chan-1:target")

	legacy, err := tc.Seal("https://hooks.example/abc")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	converted, err := tc.ReSealWithContext(legacy, ctx)
	if err != nil {
		t.Fatalf("ReSealWithContext: %v", err)
	}

	got, err := tc.OpenWithContext(converted, ctx)
	if err != nil {
		t.Fatalf("OpenWithContext after conversion: %v", err)
	}
	if got != "https://hooks.example/abc" {
		t.Errorf("plaintext survived conversion as %q", got)
	}
	// And the converted value is genuinely bound, not merely re-encrypted.
	if _, err := tc.Open(converted); !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("converted ciphertext still opens without a context: %v", err)
	}
}

// A partially-completed migration must be safe to resume. Re-running the
// conversion over an already-converted row must fail rather than double-seal,
// so the operator can convert what fails and skip what already opens.
func TestReSealWithContext_RefusesAnAlreadyConvertedCiphertext(t *testing.T) {
	tc := newTestCipher(t)
	ctx := []byte("notify_channel:chan-1:target")

	legacy, err := tc.Seal("secret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	converted, err := tc.ReSealWithContext(legacy, ctx)
	if err != nil {
		t.Fatalf("ReSealWithContext: %v", err)
	}

	if _, err := tc.ReSealWithContext(converted, ctx); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("re-running the conversion double-sealed instead of failing: %v", err)
	}
}

// Rotation must keep working through the new path, or adopting AAD would
// silently break the zero-downtime key-rotation story.
func TestOpenWithContext_FallsBackToThePreviousKey(t *testing.T) {
	oldKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	newKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ctx := []byte("notify_channel:chan-1:target")

	before, err := NewTokenCipher(oldKey)
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	sealed, err := before.SealWithContext("secret", ctx)
	if err != nil {
		t.Fatalf("SealWithContext: %v", err)
	}

	after, err := NewTokenCipherWithPrevious(newKey, oldKey)
	if err != nil {
		t.Fatalf("NewTokenCipherWithPrevious: %v", err)
	}
	got, err := after.OpenWithContext(sealed, ctx)
	if err != nil {
		t.Fatalf("OpenWithContext across rotation: %v", err)
	}
	if got != "secret" {
		t.Errorf("plaintext across rotation = %q", got)
	}

	// The context still has to match after rotation -- the fallback must not
	// quietly become an escape hatch from the binding.
	if _, err := after.OpenWithContext(sealed, []byte("other:ctx")); !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("the previous-key fallback ignored the context: %v", err)
	}
}

// The empty-plaintext decision, pinned so it cannot drift silently.
//
// Seal keeps returning "" because consumers derive "unset" from exactly that
// comparison (NotificationChannel.HasTarget is EncryptedTarget != ""), and rows
// already store "" with that meaning. SealWithContext does NOT inherit the
// special case, so a blanked secret is distinguishable from an absent one and
// carries integrity protection.
func TestEmptyPlaintext_LegacyReturnsEmptyAndContextSealsIt(t *testing.T) {
	tc := newTestCipher(t)
	ctx := []byte("notify_channel:chan-1:target")

	legacy, err := tc.Seal("")
	if err != nil {
		t.Fatalf("Seal(\"\"): %v", err)
	}
	if legacy != "" {
		t.Errorf("Seal(\"\") = %q; consumers treat the empty string as \"never set\"", legacy)
	}

	bound, err := tc.SealWithContext("", ctx)
	if err != nil {
		t.Fatalf("SealWithContext(\"\"): %v", err)
	}
	if bound == "" {
		t.Fatal("SealWithContext(\"\") returned an empty string; a blanked secret must be " +
			"distinguishable from an absent one and must be integrity-protected")
	}
	got, err := tc.OpenWithContext(bound, ctx)
	if err != nil {
		t.Fatalf("OpenWithContext of a sealed empty value: %v", err)
	}
	if got != "" {
		t.Errorf("sealed empty value round-tripped as %q", got)
	}
}

// OpenWithContext must not mirror Open's empty-string passthrough: returning
// ("", nil) for "" would let an attacker blank a column and have it read back as
// a valid empty secret.
func TestOpenWithContext_RejectsAnEmptyCiphertext(t *testing.T) {
	tc := newTestCipher(t)

	if _, err := tc.OpenWithContext("", []byte("ctx")); !errors.Is(err, ErrCiphertextCorrupted) {
		t.Fatalf("OpenWithContext(\"\") = %v; want ErrCiphertextCorrupted so a blanked "+
			"column cannot read back as a valid empty secret", err)
	}
}

// A context mismatch must be indistinguishable from tampering, not reported as
// its own error class -- the caller learns "this did not authenticate", nothing
// more granular.
func TestOpenWithContext_MismatchIsNotDistinguishableFromTampering(t *testing.T) {
	tc := newTestCipher(t)
	sealed, err := tc.SealWithContext("secret", []byte("a"))
	if err != nil {
		t.Fatalf("SealWithContext: %v", err)
	}

	_, mismatchErr := tc.OpenWithContext(sealed, []byte("b"))
	if !errors.Is(mismatchErr, ErrDecryptionFailed) {
		t.Fatalf("context mismatch = %v, want ErrDecryptionFailed", mismatchErr)
	}
	// And it must not leak the expected context back to the caller.
	if strings.Contains(mismatchErr.Error(), "a") && strings.Contains(mismatchErr.Error(), "b") {
		t.Errorf("error echoes the context values: %v", mismatchErr)
	}
}

// OpenWithContextOrLegacy is the transition reader. It is what turns adopting
// AAD into a two-deploy change instead of a four-deploy one, so its behaviour on
// each input class is pinned.

func TestOpenWithContextOrLegacy_ReadsBothFormsAndReportsWhich(t *testing.T) {
	tc := newTestCipher(t)
	ctx := []byte("notify_channel:chan-1:target")

	legacy, err := tc.Seal("secret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	bound, err := tc.SealWithContext("secret", ctx)
	if err != nil {
		t.Fatalf("SealWithContext: %v", err)
	}

	pt, isBound, err := tc.OpenWithContextOrLegacy(legacy, ctx)
	if err != nil || pt != "secret" {
		t.Fatalf("legacy read = (%q, %v)", pt, err)
	}
	if isBound {
		t.Error("a legacy ciphertext reported itself as bound; nothing would ever convert")
	}

	pt, isBound, err = tc.OpenWithContextOrLegacy(bound, ctx)
	if err != nil || pt != "secret" {
		t.Fatalf("bound read = (%q, %v)", pt, err)
	}
	if !isBound {
		t.Error("a bound ciphertext reported itself as legacy; it would be re-converted forever")
	}
}

// The fallback must not become a way to bypass the binding. A ciphertext bound
// to ANOTHER context is not legacy — it must fail, not silently fall through to
// the unbound read.
func TestOpenWithContextOrLegacy_DoesNotAcceptAnotherRowsBoundCiphertext(t *testing.T) {
	tc := newTestCipher(t)

	sealed, err := tc.SealWithContext("secret", []byte("notify_channel:chan-1:target"))
	if err != nil {
		t.Fatalf("SealWithContext: %v", err)
	}

	_, _, err = tc.OpenWithContextOrLegacy(sealed, []byte("notify_channel:chan-2:target"))
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("a ciphertext bound to another row was accepted via the legacy fallback: %v", err)
	}
}

// An unset column is not a migration candidate. Returning an error here would
// fail every row that legitimately has no secret.
func TestOpenWithContextOrLegacy_TreatsEmptyAsUnsetNotCorrupt(t *testing.T) {
	tc := newTestCipher(t)

	pt, bound, err := tc.OpenWithContextOrLegacy("", []byte("ctx"))
	if err != nil || pt != "" || bound {
		t.Fatalf("empty ciphertext = (%q, %v, %v); want (\"\", false, nil)", pt, bound, err)
	}
}
