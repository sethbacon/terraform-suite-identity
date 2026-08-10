// Package crypto provides AES-256-GCM authenticated encryption for sensitive
// values that must be stored at rest in the database — OAuth tokens, webhook
// destination URLs, OIDC client secrets, and similar capability-bearing
// secrets shared across the Terraform suite apps. AES-256-GCM is chosen
// because it provides both confidentiality and authenticated integrity,
// ensuring stored secrets cannot be silently tampered with even if the
// database is partially compromised.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

var (
	// ErrKeyLengthInvalid is returned when a master key is not exactly 32 bytes (required for AES-256).
	ErrKeyLengthInvalid = errors.New("crypto: key must be exactly 32 bytes for AES-256")
	// ErrCiphertextCorrupted is returned when the ciphertext fails base64 decoding or is too short to contain a valid nonce.
	ErrCiphertextCorrupted = errors.New("crypto: ciphertext is corrupted or tampered")
	// ErrDecryptionFailed is returned when AES-GCM authentication or decryption fails, indicating tampering or a wrong key.
	ErrDecryptionFailed = errors.New("crypto: decryption operation failed")
	// ErrSaltTooShort is returned when the provided salt is fewer than 16 bytes, which would weaken PBKDF2 key derivation.
	ErrSaltTooShort = errors.New("crypto: salt must be at least 16 bytes")
	// ErrIterationsTooLow is returned when a caller asks DeriveTokenCipher for
	// fewer than MinPBKDF2Iterations rounds. It is an ERROR rather than a silent
	// upgrade: a caller that named a weak work factor has a belief about the
	// cost of its own key derivation, and quietly deriving with a different one
	// leaves that belief in place.
	ErrIterationsTooLow = errors.New("crypto: PBKDF2 iterations below the minimum work factor")
)

// MinPBKDF2Iterations is the lowest PBKDF2-HMAC-SHA256 work factor
// DeriveTokenCipher will accept, matching current OWASP guidance (600,000).
//
// The previous guard read `if iterations < 10000 { iterations = 100000 }`,
// which was effectively inverted: a caller passing 1 was silently upgraded to a
// reasonable 100,000, while a caller passing exactly 10,000 was honoured as-is.
// The weakest value the API actually accepted was therefore an order of
// magnitude below guidance, and it was reachable ONLY by a caller who had
// thought about the number — the opposite of the intended failure mode.
const MinPBKDF2Iterations = 600000

// DefaultPBKDF2Iterations is the work factor DeriveTokenCipher uses when the
// caller expresses no preference (iterations <= 0).
const DefaultPBKDF2Iterations = 600000

// TokenCipher encrypts and decrypts sensitive token data.
// It supports dual-key decryption for zero-downtime key rotation:
// encryption always uses the current (primary) key, while decryption
// tries the primary key first, then falls back to the previous key.
type TokenCipher struct {
	masterKey   []byte
	previousKey []byte // optional, used for decryption fallback during key rotation
}

// NewTokenCipher creates a cipher with a 32-byte master key
func NewTokenCipher(masterKey []byte) (*TokenCipher, error) {
	if len(masterKey) != 32 {
		return nil, ErrKeyLengthInvalid
	}
	keyCopy := make([]byte, 32)
	copy(keyCopy, masterKey)
	return &TokenCipher{masterKey: keyCopy}, nil
}

// NewTokenCipherWithPrevious creates a cipher that supports dual-key decryption.
// The current key is used for all encryption. Decryption first tries the current
// key; if that fails with an authentication error, it retries with previousKey.
// This enables zero-downtime rotation: set the new key as current, the old key
// as previous, restart pods, then re-encrypt all tokens in a background job.
func NewTokenCipherWithPrevious(currentKey, previousKey []byte) (*TokenCipher, error) {
	if len(currentKey) != 32 {
		return nil, ErrKeyLengthInvalid
	}
	if len(previousKey) != 0 && len(previousKey) != 32 {
		return nil, ErrKeyLengthInvalid
	}
	curCopy := make([]byte, 32)
	copy(curCopy, currentKey)
	tc := &TokenCipher{masterKey: curCopy}
	if len(previousKey) == 32 {
		prevCopy := make([]byte, 32)
		copy(prevCopy, previousKey)
		tc.previousKey = prevCopy
	}
	return tc, nil
}

// DeriveTokenCipher creates a cipher by deriving a key from a passphrase.
//
// iterations <= 0 means "no preference" and uses DefaultPBKDF2Iterations. Any
// other value below MinPBKDF2Iterations is REJECTED with ErrIterationsTooLow
// rather than silently rewritten — see MinPBKDF2Iterations for why the previous
// silent-upgrade guard let the weakest accepted value through.
func DeriveTokenCipher(passphrase string, salt []byte, iterations int) (*TokenCipher, error) {
	if len(salt) < 16 {
		return nil, ErrSaltTooShort
	}
	if iterations <= 0 {
		iterations = DefaultPBKDF2Iterations
	}
	if iterations < MinPBKDF2Iterations {
		return nil, fmt.Errorf("%w: got %d, minimum is %d", ErrIterationsTooLow, iterations, MinPBKDF2Iterations)
	}
	derivedKey := pbkdf2.Key([]byte(passphrase), salt, iterations, 32, sha256.New)
	return NewTokenCipher(derivedKey)
}

// Seal encrypts plaintext and returns a base64-encoded ciphertext.
//
// The resulting ciphertext carries NO binding to the row, column or purpose it
// belongs to, so anyone with database write access can move a sealed value
// between rows or between fields and GCM will authenticate it happily — for
// example swapping one notification channel's encrypted target for another's.
// Prefer SealWithContext for anything new; this remains for ciphertexts already
// at rest (#153).
//
// An empty plaintext is returned as an empty string rather than a ciphertext,
// which makes "explicitly blanked" indistinguishable from "never set" and leaves
// it with no integrity protection. That behaviour is preserved deliberately —
// callers and stored rows depend on the empty string meaning "unset", and
// consumers derive flags such as HasTarget from exactly that comparison.
// SealWithContext does not carry the special case forward.
func (tc *TokenCipher) Seal(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	return tc.seal(plaintext, nil)
}

// SealWithContext encrypts plaintext and binds the ciphertext to context, which
// is passed as GCM additional authenticated data. The context is NOT secret and
// is NOT stored: the opener must reconstruct the identical bytes, and Open fails
// if it cannot. That is the point — it is what stops a sealed value being lifted
// from one row and replayed into another (#153).
//
// The context should name where the value lives, specifically enough that no two
// storage slots share one. A row id plus column is the usual shape:
//
//	ctx := []byte("notify_channel:" + ch.ID + ":target")
//	sealed, err := tc.SealWithContext(target, ctx)
//
// Deriving it from the same record it protects is what makes the binding hold;
// a constant, or anything an attacker also controls, buys nothing.
//
// Unlike Seal, an empty plaintext is sealed like any other value, so a blanked
// secret is distinguishable from an absent one and is integrity-protected.
func (tc *TokenCipher) SealWithContext(plaintext string, context []byte) (string, error) {
	return tc.seal(plaintext, context)
}

// seal is the single encryption path. additionalData is nil for the legacy Seal.
func (tc *TokenCipher) seal(plaintext string, additionalData []byte) (string, error) {
	blockCipher, err := aes.NewCipher(tc.masterKey)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	sealed := aead.Seal(nonce, nonce, []byte(plaintext), additionalData)
	return base64.URLEncoding.EncodeToString(sealed), nil
}

// Open decrypts a base64-encoded ciphertext and returns the plaintext.
// When a previous key is configured, Open tries the current key first;
// if GCM authentication fails it retries with the previous key before
// returning an error.
func (tc *TokenCipher) Open(encodedCiphertext string) (string, error) {
	if encodedCiphertext == "" {
		return "", nil
	}
	return tc.open(encodedCiphertext, nil)
}

// OpenWithContext decrypts a ciphertext produced by SealWithContext, requiring
// the identical context bytes. A mismatch fails as ErrDecryptionFailed — the
// same result as a wrong key or tampered bytes, because to GCM it is the same
// class of failure.
//
// There is no cross-compatibility between the two pairs, by construction: a
// ciphertext from Seal does not open here, and one from SealWithContext does not
// open with Open. That is what makes the binding meaningful, and it is why
// adopting this on existing data needs ReSealWithContext rather than a
// deploy-and-hope.
//
// The previous-key rotation fallback applies here exactly as it does to Open.
func (tc *TokenCipher) OpenWithContext(encodedCiphertext string, context []byte) (string, error) {
	if encodedCiphertext == "" {
		return "", ErrCiphertextCorrupted
	}
	return tc.open(encodedCiphertext, context)
}

// OpenWithContextOrLegacy opens a ciphertext that may be either bound
// (SealWithContext) or unbound (Seal), trying the bound form first, and reports
// which it was.
//
// This is what makes adopting AAD a two-deploy change rather than a four-deploy
// one. Without it a consumer is stuck: switching writes to SealWithContext
// breaks reads of rows not yet converted, and converting rows first breaks the
// still-running previous release — so it needs a read-both release, then a
// backfill, then a write-switch, then a cleanup. With it, a consumer ships
// read-both and write-bound together and rows convert as they are touched:
//
//	pt, bound, err := tc.OpenWithContextOrLegacy(row.Secret, ctx)
//	if err != nil { return err }
//	if !bound {
//	    if sealed, err := tc.SealWithContext(pt, ctx); err == nil {
//	        _ = store.UpdateSecret(row.ID, sealed) // opportunistic, best-effort
//	    }
//	}
//
// A backfill is then only needed for rows nothing reads, and is the same loop
// built on ReSealWithContext.
//
// A ciphertext bound to a DIFFERENT context is not legacy and must not be
// accepted: the bound read fails, the unbound read fails too (its AAD was not
// nil), and the caller gets an error. The fallback widens which formats are
// accepted, never which contexts.
//
// An empty ciphertext returns ("", false, nil), matching Open rather than
// OpenWithContext — an unset column is not a migration candidate, and treating
// it as corrupt would fail every row that legitimately holds no secret.
//
// This is a transition tool, not a permanent API. Leaving it in place after the
// data is converted keeps accepting unbound ciphertexts, which is the property
// being retired; callers should move to OpenWithContext once the backfill is
// complete.
func (tc *TokenCipher) OpenWithContextOrLegacy(encodedCiphertext string, context []byte) (string, bool, error) {
	if encodedCiphertext == "" {
		return "", false, nil
	}

	if plaintext, err := tc.open(encodedCiphertext, context); err == nil {
		return plaintext, true, nil
	}

	plaintext, err := tc.open(encodedCiphertext, nil)
	if err != nil {
		return "", false, err
	}
	return plaintext, false, nil
}

// ReSealWithContext converts a ciphertext written by Seal into one bound to
// context, without the plaintext leaving this function.
//
// It exists so the migration is written once here rather than twice in the
// consuming backends: the sealed values live in THEIR databases (the notify
// channel target, SCM app credentials), the key only exists in the running
// application, and no SQL migration can re-encrypt AES-GCM. Each consumer's
// migration is therefore a read/convert/write loop over its own rows, and this
// is the convert step.
//
// The read side uses the legacy no-AAD path including the previous-key fallback,
// so rows written before a key rotation convert correctly too. Re-running it
// over an already-converted row fails with ErrDecryptionFailed rather than
// double-sealing, which makes a partially-completed migration safe to resume:
// convert what fails, skip what succeeds under OpenWithContext.
func (tc *TokenCipher) ReSealWithContext(encodedCiphertext string, context []byte) (string, error) {
	plaintext, err := tc.Open(encodedCiphertext)
	if err != nil {
		return "", err
	}
	return tc.SealWithContext(plaintext, context)
}

// open is the single decryption path, including the rotation fallback.
func (tc *TokenCipher) open(encodedCiphertext string, additionalData []byte) (string, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return "", ErrCiphertextCorrupted
	}

	// Try current key first
	plaintext, err := tc.decryptWithKey(tc.masterKey, ciphertext, additionalData)
	if err == nil {
		return plaintext, nil
	}

	// If we have a previous key and the error was an authentication failure,
	// try the previous key (the ciphertext may have been encrypted before rotation).
	if tc.previousKey != nil && errors.Is(err, ErrDecryptionFailed) {
		plaintext, prevErr := tc.decryptWithKey(tc.previousKey, ciphertext, additionalData)
		if prevErr == nil {
			return plaintext, nil
		}
	}

	return "", err
}

// decryptWithKey performs AES-256-GCM decryption with the given key.
// additionalData must match what was supplied at Seal time; nil for the legacy
// no-AAD path.
func (tc *TokenCipher) decryptWithKey(key, ciphertext, additionalData []byte) (string, error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return "", err
	}

	nonceLen := aead.NonceSize()
	if len(ciphertext) < nonceLen {
		return "", ErrCiphertextCorrupted
	}

	nonce := ciphertext[:nonceLen]
	actualCiphertext := ciphertext[nonceLen:]

	plaintext, err := aead.Open(nil, nonce, actualCiphertext, additionalData)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	return string(plaintext), nil
}

// GenerateKey creates a cryptographically secure random 32-byte key
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateSalt creates a cryptographically secure random salt
func GenerateSalt(length int) ([]byte, error) {
	if length < 16 {
		length = 16
	}
	salt := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}
