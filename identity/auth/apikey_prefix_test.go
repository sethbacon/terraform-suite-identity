// apikey_prefix_test.go guards the property that makes the persisted
// key_prefix usable as an AUTHENTICATION DISCRIMINATOR rather than merely as a
// human-readable label (issue #136).
//
// The distinction is the whole bug. key_prefix is the sole narrowing predicate
// of the real authentication lookup, and each row it fails to exclude costs the
// authenticating host one bcrypt comparison at BcryptCost. So the number of
// RANDOM characters that survive into it is a security parameter, and it is one
// that a caller-supplied label can silently consume: displayPrefix is the first
// DisplayPrefixLength bytes of "<prefix>_<randomPart>", so the label and the
// randomness compete for one fixed-size window.
//
// MaxAPIKeyPrefixLength was previously 20, which lost that competition
// outright — at 9 bytes or more the window holds no randomness at all and every
// key the application issues shares one byte-identical prefix. That value was
// not an oversight of inattention; it was derived carefully and correctly from
// bcrypt's 72-byte input window by someone who had no reason to think a second
// limit applied. Which is exactly why the relationship is now enforced by the
// compiler in apikey.go and asserted behaviourally here, instead of being
// explained in a comment for the next person to also not think about.
//
// Both directions are covered: a prefix at the cap must still WORK (the fix
// must not be achieved by refusing everything), and the discriminator must
// actually discriminate across the whole accepted range.
package auth

import (
	"fmt"
	"strings"
	"testing"
)

// TestDisplayPrefix_RetainsRandomness_AcrossEveryAcceptedPrefixLength is the
// core invariant: for EVERY prefix length GenerateAPIKey accepts, the persisted
// display prefix carries at least MinPrefixRandomChars characters that came
// from the random part.
//
// Sweeping the whole accepted range rather than probing the boundary is
// deliberate. The defect was a constant permitting a range whose far end was
// degenerate, so a test that only checked one length could be satisfied by a
// cap that happened to be safe at the length chosen.
func TestDisplayPrefix_RetainsRandomness_AcrossEveryAcceptedPrefixLength(t *testing.T) {
	for n := 0; n <= MaxAPIKeyPrefixLength; n++ {
		prefix := strings.Repeat("p", n)
		t.Run(fmt.Sprintf("prefix-len-%d", n), func(t *testing.T) {
			key, _, displayPrefix, err := GenerateAPIKey(prefix)
			if err != nil {
				t.Fatalf("GenerateAPIKey(%d-byte prefix) = %v, want success", n, err)
			}

			// The fixed portion is everything the caller controls: the label
			// plus the separator. Whatever the window holds beyond it came
			// from randomPart.
			fixed := len(prefix) + len("_")
			randomChars := len(displayPrefix) - fixed
			if randomChars < MinPrefixRandomChars {
				t.Fatalf("a %d-byte prefix leaves %d random characters in the %d-byte key_prefix %q, want at least %d; "+
					"with fewer, the lookup stops narrowing the candidate set and every key sharing this label "+
					"lands in the same bucket",
					n, randomChars, DisplayPrefixLength, displayPrefix, MinPrefixRandomChars)
			}
			if !strings.HasPrefix(key, displayPrefix) {
				t.Fatalf("display prefix %q is not a prefix of the key it identifies", displayPrefix)
			}
		})
	}
}

// TestDisplayPrefix_DiffersBetweenKeysSharingOneLabel reproduces the issue's own
// verification method: generate several keys under ONE label and count the
// distinct display prefixes.
//
// This is the observable form of the defect. Under the old cap, five keys
// minted with a 10- or 18-byte prefix produced exactly ONE distinct display
// prefix — so a single unauthenticated request carrying that public label
// selected every live key in the table as a bcrypt candidate.
//
// The threshold is deliberately weak (more than one distinct value out of
// eight): the point is to catch a TOTAL collapse of the discriminator, and a
// strict "all eight distinct" assertion would be a flaky test of the birthday
// bound rather than a test of this code.
func TestDisplayPrefix_DiffersBetweenKeysSharingOneLabel(t *testing.T) {
	const keys = 8

	for _, label := range []string{"tsm", "tfr", strings.Repeat("p", MaxAPIKeyPrefixLength)} {
		t.Run(label, func(t *testing.T) {
			distinct := map[string]bool{}
			for i := 0; i < keys; i++ {
				_, _, displayPrefix, err := GenerateAPIKey(label)
				if err != nil {
					t.Fatalf("GenerateAPIKey(%q) = %v", label, err)
				}
				distinct[displayPrefix] = true
			}
			if len(distinct) <= 1 {
				t.Fatalf("%d keys minted with label %q produced %d distinct key_prefix values; "+
					"the lookup discriminator has collapsed and every one of these keys would be "+
					"returned as a bcrypt candidate for any request presenting the label",
					keys, label, len(distinct))
			}
		})
	}
}

// TestMaxAPIKeyPrefixLength_LeavesRoomInTheLookupWindow states the constant
// relationship in the test suite as well as in the compiler.
//
// The compile-time assertion in apikey.go is the control that cannot be
// skipped; this is the one that EXPLAINS a failure. A build error on a
// `uint(...)` conversion names neither the constant at fault nor the reason,
// so someone raising the cap deserves to also see a sentence about why they
// cannot.
func TestMaxAPIKeyPrefixLength_LeavesRoomInTheLookupWindow(t *testing.T) {
	fixed := MaxAPIKeyPrefixLength + len("_")
	if got := DisplayPrefixLength - fixed; got < MinPrefixRandomChars {
		t.Fatalf("MaxAPIKeyPrefixLength (%d) plus the separator fills %d of the %d-byte key_prefix window, "+
			"leaving %d random characters, want at least %d — a prefix this long stops the lookup "+
			"discriminating between keys",
			MaxAPIKeyPrefixLength, fixed, DisplayPrefixLength, got, MinPrefixRandomChars)
	}
}

// TestGenerateAPIKey_RejectsPrefixesThatWouldCollapseTheDiscriminator is the
// other direction of the cap: the lengths that produced a degenerate prefix are
// now unreachable, and the refusal says why.
//
// 9 bytes is the length at which the window held ZERO random characters, and
// it sits inside the range the old constant affirmatively blessed.
func TestGenerateAPIKey_RejectsPrefixesThatWouldCollapseTheDiscriminator(t *testing.T) {
	for _, n := range []int{MaxAPIKeyPrefixLength + 1, 9, 10, 18, 20} {
		prefix := strings.Repeat("p", n)
		_, _, _, err := GenerateAPIKey(prefix)
		if err == nil {
			t.Fatalf("GenerateAPIKey accepted a %d-byte prefix; at this length the key_prefix window "+
				"retains fewer than %d random characters", n, MinPrefixRandomChars)
		}
		if !strings.Contains(err.Error(), "MaxAPIKeyPrefixLength") {
			t.Errorf("GenerateAPIKey(%d-byte prefix) = %q, want it to name the constant at fault", n, err.Error())
		}
	}
}
