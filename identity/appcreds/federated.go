// federated.go mints Azure DevOps access tokens through workload identity
// federation: the platform (AKS, Container Apps, any OIDC-capable host)
// projects a service-account token, and that token is exchanged for an Entra
// one. No client secret exists, so there is nothing to store, rotate or leak.
//
// This is the credential type Microsoft recommends over a client secret, which
// Entra caps at 24 months and advises against in production.
package appcreds

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// FederatedCreds identifies a workload identity used to mint Azure DevOps
// tokens. Unlike EntraCreds there is no secret material at all: only the
// federated app registration's client id.
//
// There is deliberately no TenantID. The tenant and the path to the projected
// token come from the process environment (AZURE_TENANT_ID and
// AZURE_FEDERATED_TOKEN_FILE, set by the AKS workload-identity webhook) rather
// than from stored configuration: the record says WHICH identity to assume, and
// the platform supplies the proof. Storing a tenant beside it would create a
// second source of truth that can disagree with the projected token.
type FederatedCreds struct {
	ClientID string
}

// Validate reports whether there is an identity to assume.
func (c FederatedCreds) Validate() error {
	if strings.TrimSpace(c.ClientID) == "" {
		return fmt.Errorf("%w: workload identity federation requires client_id", ErrInvalidCreds)
	}
	return nil
}

// Fingerprint keys a cache. Namespaced so a federated client id can never
// collide with an EntraCreds fingerprint in a shared cache -- the two share the
// client id field and nothing else.
func (c FederatedCreds) Fingerprint() string {
	sum := sha256.Sum256([]byte("entra_federated\x00" + c.ClientID))
	return hex.EncodeToString(sum[:])
}

// FederatedCredential is the subset of azcore.TokenCredential this package
// needs, satisfied by *azidentity.WorkloadIdentityCredential and by a fake.
//
// Narrow on purpose: depending on the full azcore.TokenCredential would make it
// unsubstitutable without pulling the Azure SDK into every caller's tests.
type FederatedCredential interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error)
}

// FederatedCredentialFactory builds the credential for a client id.
type FederatedCredentialFactory func(clientID string) (FederatedCredential, error)

// defaultFederatedCredentialFactory is the real one. Overridden only by
// WithFederatedCredentialFactory, and only in tests.
func defaultFederatedCredentialFactory(clientID string) (FederatedCredential, error) {
	cred, err := azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
		ClientID: clientID,
	})
	if err != nil {
		// Return an UNTYPED nil rather than the failed call's result directly.
		// azidentity hands back a nil *WorkloadIdentityCredential alongside its
		// error, and a nil concrete pointer stored in an interface makes a
		// NON-nil interface value -- so `cred, err := factory(...); if cred !=
		// nil` would be true and the first method call on it would panic.
		// Every caller here checks err first, but a factory whose contract only
		// holds for callers who get the order right is a trap for the next one.
		return nil, err
	}
	return cred, nil
}

// MintFederated exchanges the platform-projected token for an Azure DevOps
// access token. It returns the same Token shape as MintEntra, so a caller's
// caching is identical whichever credential type a record carries.
func (m *Minter) MintFederated(ctx context.Context, creds FederatedCreds) (Token, error) {
	if err := creds.Validate(); err != nil {
		return Token{}, err
	}

	cred, err := m.credentialFactory(strings.TrimSpace(creds.ClientID))
	if err != nil {
		// The common cause is running somewhere the workload-identity webhook
		// never ran, so AZURE_FEDERATED_TOKEN_FILE is simply absent. Say that:
		// the raw SDK error names an environment variable without explaining
		// which deployment shape is expected to set it, and an operator has to
		// be able to tell "this host cannot federate at all" apart from "these
		// credentials are wrong".
		return Token{}, fmt.Errorf(
			"appcreds: could not build a workload identity credential for client_id %s "+
				"(federated auth requires the platform to project a token -- on AKS that is the "+
				"workload-identity webhook setting AZURE_TENANT_ID and AZURE_FEDERATED_TOKEN_FILE): %w",
			creds.ClientID, err)
	}

	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{AzureDevOpsResourceID + "/.default"},
	})
	if err != nil {
		return Token{}, fmt.Errorf("appcreds: mint federated Azure DevOps token: %w", err)
	}
	if tok.Token == "" {
		// A credential reporting success with nothing in it would otherwise be
		// cached and sent upstream as an empty bearer token, failing later and
		// somewhere else.
		return Token{}, fmt.Errorf("appcreds: federated token exchange returned an empty token")
	}
	return Token{AccessToken: tok.Token, ExpiresAt: tok.ExpiresOn}, nil
}
