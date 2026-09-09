package appcreds

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// fakeManagedIdentityFactory records the client id the mint asked for -- the
// only input a managed-identity mint has, and therefore the only thing that
// selects which principal the token represents.
type fakeManagedIdentityFactory struct {
	cred     *fakeFederatedCredential
	buildErr error
	clientID string
	calls    int
}

func (f *fakeManagedIdentityFactory) factory() ManagedIdentityCredentialFactory {
	return func(clientID string) (FederatedCredential, error) {
		f.calls++
		f.clientID = clientID
		if f.buildErr != nil {
			return nil, f.buildErr
		}
		return f.cred, nil
	}
}

func TestMintManagedIdentity_Success(t *testing.T) {
	expiry := testNow.Add(time.Hour)
	fake := &fakeManagedIdentityFactory{cred: &fakeFederatedCredential{
		token: azcore.AccessToken{Token: "mi-ado-token", ExpiresOn: expiry}}}
	m := New(WithManagedIdentityCredentialFactory(fake.factory()), WithClock(fixedClock(testNow)))

	tok, err := m.MintManagedIdentity(context.Background(), ManagedIdentityCreds{ClientID: "  uami-1  "})
	if err != nil {
		t.Fatalf("MintManagedIdentity: %v", err)
	}
	if tok.AccessToken != "mi-ado-token" {
		t.Errorf("token = %q, want mi-ado-token", tok.AccessToken)
	}
	// The platform reports its own expiry; unlike the client-credentials grant
	// there is no expires_in to convert, so it is passed through.
	if !tok.ExpiresAt.Equal(expiry) {
		t.Errorf("expiry = %v, want the credential's %v", tok.ExpiresAt, expiry)
	}
	if fake.clientID != "uami-1" {
		t.Errorf("credential built for %q -- surrounding whitespace was not trimmed", fake.clientID)
	}
	if len(fake.cred.scopes) != 1 || fake.cred.scopes[0] != AzureDevOpsResourceID+"/.default" {
		t.Errorf("scopes = %v, want the Azure DevOps resource id", fake.cred.scopes)
	}
}

// An empty client id would select the SYSTEM-assigned identity -- a different
// principal with different Azure DevOps grants. Minting as the wrong principal
// is far worse than not minting, so it is refused before the SDK sees it.
func TestMintManagedIdentity_EmptyClientIDIsRefusedNotDefaulted(t *testing.T) {
	fake := &fakeManagedIdentityFactory{cred: &fakeFederatedCredential{}}
	m := New(WithManagedIdentityCredentialFactory(fake.factory()))

	for _, id := range []string{"", "   "} {
		_, err := m.MintManagedIdentity(context.Background(), ManagedIdentityCreds{ClientID: id})
		if err == nil {
			t.Fatalf("client id %q minted", id)
		}
		if !errors.Is(err, ErrInvalidCreds) {
			t.Errorf("error %v is not ErrInvalidCreds, so a caller cannot report it as a 400", err)
		}
		if !strings.Contains(err.Error(), "system-assigned") {
			t.Errorf("error does not explain what an empty id would silently select: %v", err)
		}
	}
	if fake.calls != 0 {
		t.Errorf("the factory was called %d times with no identity, want 0", fake.calls)
	}
}

// A managed-identity mint must never touch the Entra token endpoint: the
// platform's identity endpoint answers instead, and reaching the former would
// mean the wrong arm ran.
func TestMintManagedIdentity_NeverCallsTheClientSecretEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the client-credentials endpoint was called for a managed identity mint")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	fake := &fakeManagedIdentityFactory{cred: &fakeFederatedCredential{
		token: azcore.AccessToken{Token: "t", ExpiresOn: testNow.Add(time.Hour)}}}
	m := New(WithEntraLoginBaseURL(srv.URL), WithManagedIdentityCredentialFactory(fake.factory()))
	if _, err := m.MintManagedIdentity(context.Background(), ManagedIdentityCreds{ClientID: "c"}); err != nil {
		t.Fatalf("MintManagedIdentity: %v", err)
	}
}

func TestMintManagedIdentity_Failures(t *testing.T) {
	t.Run("no identity endpoint on this host", func(t *testing.T) {
		// The off-Azure case. The operator has to be able to tell "wrong
		// platform" from "wrong credentials" -- the SDK error alone says
		// neither.
		m := New(WithManagedIdentityCredentialFactory(
			(&fakeManagedIdentityFactory{buildErr: errors.New("no MSI endpoint found")}).factory()))
		_, err := m.MintManagedIdentity(context.Background(), ManagedIdentityCreds{ClientID: "c"})
		if err == nil {
			t.Fatal("building the credential failed but the mint succeeded")
		}
		if !strings.Contains(err.Error(), "Azure compute") {
			t.Errorf("error does not say the host must be Azure compute: %v", err)
		}
	})

	t.Run("the endpoint refuses the identity", func(t *testing.T) {
		fake := &fakeManagedIdentityFactory{cred: &fakeFederatedCredential{
			err: errors.New("identity not found for this resource")}}
		m := New(WithManagedIdentityCredentialFactory(fake.factory()))
		_, err := m.MintManagedIdentity(context.Background(), ManagedIdentityCreds{ClientID: "c"})
		if err == nil {
			t.Fatal("the exchange was refused but the mint succeeded")
		}
		if !strings.Contains(err.Error(), "identity not found") {
			t.Errorf("the upstream reason was dropped: %v", err)
		}
		// Both halves of the diagnosis, since at GetToken time either is possible.
		if !strings.Contains(err.Error(), "attached to this resource") {
			t.Errorf("error does not name the assignment check: %v", err)
		}
	})

	t.Run("an empty token reported as success", func(t *testing.T) {
		fake := &fakeManagedIdentityFactory{cred: &fakeFederatedCredential{
			token: azcore.AccessToken{ExpiresOn: testNow.Add(time.Hour)}}}
		m := New(WithManagedIdentityCredentialFactory(fake.factory()))
		if _, err := m.MintManagedIdentity(context.Background(), ManagedIdentityCreds{ClientID: "c"}); err == nil {
			t.Fatal("an empty token was accepted")
		}
	})
}

// Managed identity and federation carry the SAME single field. Without the type
// namespace their fingerprints would be identical, and a cache shared across
// types would serve a token minted for one as the other -- two different
// principals with different Azure DevOps grants.
func TestManagedIdentityCreds_FingerprintDoesNotCollideWithFederated(t *testing.T) {
	mi := ManagedIdentityCreds{ClientID: "same-id"}
	fed := FederatedCreds{ClientID: "same-id"}
	if mi.Fingerprint() == fed.Fingerprint() {
		t.Error("managed identity and federated hash alike for the same client id; " +
			"one principal's token would be served for the other")
	}
	if mi.Fingerprint() == (ManagedIdentityCreds{ClientID: "other"}).Fingerprint() {
		t.Error("two different identities hash alike")
	}
	// And against the two credential types that carry more fields.
	if mi.Fingerprint() == (EntraCreds{ClientID: "same-id"}).Fingerprint() {
		t.Error("managed identity hashes like a client-secret credential")
	}
}

// The DEFAULT factory is the real SDK. No test host is Azure compute, so this
// asserts what can be asserted: it is wired to azidentity, it returns an
// untyped nil on failure, and a Minter built with no options reaches it.
func TestDefaultManagedIdentityCredentialFactory_IsTheRealSDK(t *testing.T) {
	cred, err := defaultManagedIdentityCredentialFactory("some-client-id")
	if err != nil {
		if cred != nil {
			t.Errorf("the factory returned a non-nil credential (%T) alongside an error; "+
				"a caller checking the credential rather than the error would panic", cred)
		}
	} else if cred == nil {
		t.Fatal("the factory returned no credential and no error")
	}

	// A default Minter must route through that same factory, not a stub. The
	// constructor succeeds off Azure (the SDK defers detection to GetToken), so
	// this asserts the wiring rather than an error.
	if New().managedIdentityFactory == nil {
		t.Fatal("a default Minter has no managed identity factory")
	}

	// The one input the SDK's constructor genuinely rejects. It hands back a
	// nil *ManagedIdentityCredential alongside the error, and a nil concrete
	// pointer stored in an interface is a NON-nil interface value -- so a
	// caller checking the credential rather than the error would panic on first
	// use. The factory must convert it.
	cred, err = defaultManagedIdentityCredentialFactory("")
	if err == nil {
		t.Fatal("an empty client id built a credential; it would select the system-assigned identity")
	}
	if cred != nil {
		t.Errorf("empty client id returned a non-nil credential (%T) alongside an error", cred)
	}
}

// The identity SELECTION is asserted on the options, because the credential the
// SDK returns exposes nothing about which identity it will ask for.
//
// This is the mutation that matters: dropping the ID does not fail, it selects
// the SYSTEM-assigned identity -- a different principal with different Azure
// DevOps grants -- and mints successfully. Verified against the SDK: options
// with a nil ID construct without error.
func TestManagedIdentityCredentialOptions_SelectsTheUserAssignedIdentity(t *testing.T) {
	opts := managedIdentityCredentialOptions("uami-1")
	if opts.ID == nil {
		t.Fatal("no ID set: the credential would silently use the system-assigned identity")
	}
	got, ok := opts.ID.(azidentity.ClientID)
	if !ok {
		t.Fatalf("ID is %T, want azidentity.ClientID -- ResourceID and ObjectID name different principals", opts.ID)
	}
	if string(got) != "uami-1" {
		t.Errorf("ID = %q, want the client id it was given", string(got))
	}
}
