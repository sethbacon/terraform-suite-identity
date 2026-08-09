package oidc

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Issue #152 — the azp ("authorized party") claim was never checked.
//
// go-oidc's Verify checks only that our client_id appears in the audience, and
// its own source says so:
//
//	// This check DOES NOT ensure that the ClientID is the party to which the
//	// ID Token was issued (i.e. Authorized party).
//
// Audience membership is weaker than being the party the token was issued TO.
// On an IdP serving several clients, a token minted for client B that merely
// lists our client_id among its audiences passed. azp is the claim that
// separates the two.
//
// These drive checkAuthorizedParty directly rather than through a live IdP,
// because the behaviour under test is claim adjudication, not transport — and a
// test that needed a real provider would be testing go-oidc.

const testClientID = "registry-client"

// claimsOf builds the decoded-claims map checkAuthorizedPartyClaims consumes.
func claimsOf(t *testing.T, m map[string]any) map[string]json.RawMessage {
	t.Helper()
	out := map[string]json.RawMessage{}
	for k, v := range m {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal %s: %v", k, err)
		}
		out[k] = raw
	}
	return out
}

func TestCheckAuthorizedParty_RejectsATokenIssuedToAnotherClient(t *testing.T) {
	// The attack: an IdP serving several relying parties mints a token for
	// client B and lists our client_id in the audience. Audience membership
	// alone -- all go-oidc checks -- accepts it.
	err := checkAuthorizedPartyClaims(
		claimsOf(t, map[string]any{"azp": "other-client"}),
		[]string{testClientID, "other-client"}, testClientID)
	if err == nil {
		t.Fatal("accepted an ID token whose azp names a different client")
	}
	// The attacker-influenced value must not be echoed into the error, since it
	// lands in logs verbatim.
	if strings.Contains(err.Error(), "other-client") {
		t.Errorf("error echoes the attacker-supplied azp value: %v", err)
	}
}

func TestCheckAuthorizedParty_AcceptsOurOwnAzp(t *testing.T) {
	if err := checkAuthorizedPartyClaims(
		claimsOf(t, map[string]any{"azp": testClientID}),
		[]string{testClientID, "other-client"}, testClientID); err != nil {
		t.Errorf("rejected a token whose azp is our own client_id: %v", err)
	}
}

// TestCheckAuthorizedParty_MultiAudienceWithoutAzpIsRejected — a token naming
// several audiences and no authorized party binds itself to nobody.
func TestCheckAuthorizedParty_MultiAudienceWithoutAzpIsRejected(t *testing.T) {
	if err := checkAuthorizedPartyClaims(
		map[string]json.RawMessage{},
		[]string{testClientID, "other-client"}, testClientID); err == nil {
		t.Error("accepted a multi-audience token with no azp claim")
	}
}

// TestCheckAuthorizedParty_SingleAudienceWithoutAzpIsAccepted is the
// compatibility half, and it matters more than it looks: the ordinary token
// from a correctly-configured IdP has one audience and no azp. A check that
// rejected this would be turned off within a day, taking the real protection
// with it.
func TestCheckAuthorizedParty_SingleAudienceWithoutAzpIsAccepted(t *testing.T) {
	if err := checkAuthorizedPartyClaims(
		map[string]json.RawMessage{},
		[]string{testClientID}, testClientID); err != nil {
		t.Errorf("rejected the ordinary single-audience token: %v", err)
	}
}

// TestCheckAuthorizedParty_NonStringAzpIsRejected — a crafted token can carry
// any JSON type; an object or number must not slip past as "absent".
//
// It asserts the SPECIFIC error, not merely that one occurred. Rejection here
// is doubly ensured: if the type check were removed, azp would stay "" and the
// mismatch check would reject it anyway. A test asserting only `err != nil`
// therefore passes with the type check deleted — verified, it did — and would
// be guarding nothing.
func TestCheckAuthorizedParty_NonStringAzpIsRejected(t *testing.T) {
	for name, v := range map[string]any{
		"number": 42,
		"object": map[string]string{"sub": testClientID},
		"array":  []string{testClientID},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkAuthorizedPartyClaims(
				claimsOf(t, map[string]any{"azp": v}),
				[]string{testClientID, "other"}, testClientID)
			if err == nil {
				t.Fatalf("accepted a non-string azp (%s)", name)
			}
			if !strings.Contains(err.Error(), "not a string") {
				t.Errorf("error = %q; want it to name the type problem rather than "+
					"falling through to the mismatch check", err)
			}
		})
	}

	// JSON null unmarshals into a string without error, leaving "", so it is
	// caught by the mismatch check rather than the type check. Asserted
	// separately so the case above can pin the type check exactly.
	if err := checkAuthorizedPartyClaims(
		claimsOf(t, map[string]any{"azp": nil}),
		[]string{testClientID, "other"}, testClientID); err == nil {
		t.Error("accepted a null azp")
	}
}

// TestExchangeAndVerify_CallsTheAuthorizedPartyCheck is a wiring guard.
//
// The adjudication being correct is worth nothing if nothing calls it, and
// ExchangeAndVerify cannot be exercised in a unit test without a live IdP — so
// deleting the call site breaks no behavioural test. This reads the source
// instead, which is the only thing that can fail when the check is unwired.
func TestExchangeAndVerify_CallsTheAuthorizedPartyCheck(t *testing.T) {
	src, err := os.ReadFile("provider.go")
	if err != nil {
		t.Fatalf("read provider.go: %v", err)
	}

	fn := string(src)
	start := strings.Index(fn, "func (p *Provider) ExchangeAndVerify(")
	if start < 0 {
		t.Fatal("ExchangeAndVerify not found — this guard is not reading the right function")
	}
	end := strings.Index(fn[start:], "\n}\n")
	if end < 0 {
		t.Fatal("could not find the end of ExchangeAndVerify")
	}
	body := fn[start : start+end]

	if !strings.Contains(body, "checkAuthorizedParty(") {
		t.Error("ExchangeAndVerify does not call checkAuthorizedParty. The azp rules " +
			"are enforced nowhere, and no behavioural test can see that because the " +
			"function needs a live IdP (issue #152).")
	}
	// Order matters: a replayed token should be reported as a replay, not as an
	// audience problem.
	if n, a := strings.Index(body, "idToken.Nonce"), strings.Index(body, "checkAuthorizedParty("); n >= 0 && a >= 0 && a < n {
		t.Error("the azp check runs before the nonce check; a replayed token would be " +
			"reported as an audience failure")
	}
}
