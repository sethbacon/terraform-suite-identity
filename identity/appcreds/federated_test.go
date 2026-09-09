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
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// fakeFederatedCredential stands in for the projected-token exchange, which no
// test host can perform: it needs a platform that projects a service-account
// token.
type fakeFederatedCredential struct {
	token    azcore.AccessToken
	err      error
	scopes   []string
	calls    int
	clientID string
}

func (f *fakeFederatedCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.calls++
	f.scopes = opts.Scopes
	return f.token, f.err
}

// fakeFactory records the client id it was asked for -- the only input a
// federated mint has, and therefore the only thing that selects the identity.
func fakeFactory(cred *fakeFederatedCredential, buildErr error) FederatedCredentialFactory {
	return func(clientID string) (FederatedCredential, error) {
		cred.clientID = clientID
		if buildErr != nil {
			return nil, buildErr
		}
		return cred, nil
	}
}

func TestMintFederated_Success(t *testing.T) {
	expiry := testNow.Add(time.Hour)
	cred := &fakeFederatedCredential{token: azcore.AccessToken{Token: "federated-token", ExpiresOn: expiry}}
	m := newTestMinter(t, WithFederatedCredentialFactory(fakeFactory(cred, nil)), WithClock(fixedClock(testNow)))

	tok, err := m.MintFederated(context.Background(), FederatedCreds{ClientID: "  fed-client-1  "})
	if err != nil {
		t.Fatalf("MintFederated: %v", err)
	}
	if tok.AccessToken != "federated-token" {
		t.Errorf("token = %q", tok.AccessToken)
	}
	// The credential reports its own expiry; unlike the client-credentials
	// grant there is no expires_in to convert, so this must be passed through
	// rather than recomputed from the clock.
	if !tok.ExpiresAt.Equal(expiry) {
		t.Errorf("expiry = %v, want the credential's %v", tok.ExpiresAt, expiry)
	}
	if cred.clientID != "fed-client-1" {
		t.Errorf("credential built for %q -- surrounding whitespace was not trimmed", cred.clientID)
	}
	if len(cred.scopes) != 1 || cred.scopes[0] != AzureDevOpsResourceID+"/.default" {
		t.Errorf("scopes = %v, want the Azure DevOps resource id", cred.scopes)
	}
}

// A federated mint must never touch the Entra token endpoint: there is no
// client secret to send, and reaching it would mean the wrong arm ran.
func TestMintFederated_NeverCallsTheClientSecretEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the client-credentials endpoint was called for a federated mint")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cred := &fakeFederatedCredential{token: azcore.AccessToken{Token: "t", ExpiresOn: testNow.Add(time.Hour)}}
	m := newTestMinter(t, WithEntraLoginBaseURL(srv.URL), WithFederatedCredentialFactory(fakeFactory(cred, nil)))
	if _, err := m.MintFederated(context.Background(), FederatedCreds{ClientID: "c"}); err != nil {
		t.Fatalf("MintFederated: %v", err)
	}
}

func TestMintFederated_Failures(t *testing.T) {
	t.Run("no client id", func(t *testing.T) {
		cred := &fakeFederatedCredential{}
		m := newTestMinter(t, WithFederatedCredentialFactory(fakeFactory(cred, nil)))
		for _, id := range []string{"", "   "} {
			_, err := m.MintFederated(context.Background(), FederatedCreds{ClientID: id})
			if err == nil {
				t.Fatalf("client id %q minted", id)
			}
			if !errors.Is(err, ErrInvalidCreds) {
				t.Errorf("error %v is not ErrInvalidCreds", err)
			}
		}
		if cred.calls != 0 {
			t.Errorf("exchange attempted %d times with no identity, want 0", cred.calls)
		}
	})

	t.Run("the platform projects no token", func(t *testing.T) {
		// The realistic failure: running somewhere the workload-identity webhook
		// never ran, so AZURE_FEDERATED_TOKEN_FILE is absent.
		m := newTestMinter(t, WithFederatedCredentialFactory(
			fakeFactory(&fakeFederatedCredential{}, errors.New("AZURE_FEDERATED_TOKEN_FILE is not set"))))
		_, err := m.MintFederated(context.Background(), FederatedCreds{ClientID: "c"})
		if err == nil {
			t.Fatal("building the credential failed but the mint succeeded")
		}
		// An operator has to be able to tell "this host cannot federate at all"
		// from "these credentials are wrong". The bare SDK error does not say.
		for _, want := range []string{"AZURE_FEDERATED_TOKEN_FILE", "workload-identity"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error does not mention %q: %v", want, err)
			}
		}
	})

	t.Run("the exchange is rejected", func(t *testing.T) {
		m := newTestMinter(t, WithFederatedCredentialFactory(fakeFactory(
			&fakeFederatedCredential{err: errors.New("AADSTS700213: no matching federated identity record")}, nil)))
		_, err := m.MintFederated(context.Background(), FederatedCreds{ClientID: "c"})
		if err == nil {
			t.Fatal("the exchange was rejected but the mint succeeded")
		}
		if !strings.Contains(err.Error(), "AADSTS700213") {
			t.Errorf("the upstream reason was dropped: %v", err)
		}
	})

	t.Run("an empty token reported as success", func(t *testing.T) {
		// Would otherwise be cached and sent upstream as an empty bearer token,
		// failing later and somewhere else.
		m := newTestMinter(t, WithFederatedCredentialFactory(fakeFactory(
			&fakeFederatedCredential{token: azcore.AccessToken{ExpiresOn: testNow.Add(time.Hour)}}, nil)))
		if _, err := m.MintFederated(context.Background(), FederatedCreds{ClientID: "c"}); err == nil {
			t.Fatal("an empty token was accepted")
		}
	})
}

// The DEFAULT factory is the real azidentity one, and no test host projects a
// token, so this asserts what can be asserted: it is wired to the SDK, it
// returns an error rather than panicking or handing back a nil credential, and
// a Minter built with no options routes through it.
//
// Without this the default is only ever exercised in production, where "the
// factory was accidentally left as a stub" looks exactly like a platform
// misconfiguration.
func TestDefaultFederatedCredentialFactory_IsTheRealSDK(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "")
	t.Setenv("AZURE_CLIENT_ID", "")

	cred, err := defaultFederatedCredentialFactory("some-client-id")
	if err == nil {
		// Some hosts genuinely can federate. Then the credential must be real.
		if cred == nil {
			t.Fatal("the factory returned no credential and no error")
		}
		return
	}
	// A nil CONCRETE pointer stored in an interface is a non-nil interface
	// value, and azidentity returns exactly that on failure. The factory has to
	// convert it, or a caller checking the credential instead of the error gets
	// a nil-pointer panic on the first method call.
	if cred != nil {
		t.Errorf("the factory returned a non-nil credential (%T) alongside an error; "+
			"a caller checking the credential rather than the error would panic", cred)
	}

	// A Minter with no options must reach that same factory, not a stub.
	_, mintErr := New().MintFederated(context.Background(), FederatedCreds{ClientID: "some-client-id"})
	if mintErr == nil {
		t.Fatal("a default Minter minted a federated token with no projected token available")
	}
	if !strings.Contains(mintErr.Error(), "AZURE_FEDERATED_TOKEN_FILE") {
		t.Errorf("the default path does not explain what the platform must provide: %v", mintErr)
	}
}
