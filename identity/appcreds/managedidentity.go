// managedidentity.go mints Azure DevOps access tokens from a user-assigned
// MANAGED IDENTITY: the hosting platform holds the credential entirely, and the
// process asks its local identity endpoint for a token.
//
// There is no secret and no certificate anywhere -- not in the database, not in
// the environment, not in transit to Entra. In that respect it is the strongest
// of the four credential types, and on Azure compute it is the one Microsoft
// points to first.
//
// The catch, and the reason the registry gates it behind an operator
// declaration rather than offering it everywhere: it only works ON Azure. The
// SDK reaches a link-local metadata service (169.254.169.254) or a
// platform-injected IDENTITY_ENDPOINT, neither of which exists off Azure, and
// the failure off-platform is a connection timeout rather than a clean refusal.
package appcreds

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// ManagedIdentityCreds selects a user-assigned managed identity by client id.
//
// Deliberately no TenantID and no secret material, exactly like FederatedCreds:
// the platform holds the identity and supplies the tenant. The client id is not
// optional here even though the SDK would accept its absence -- an empty id
// selects the SYSTEM-assigned identity, which is a different identity with
// different Azure DevOps grants, and silently falling back to it is the kind of
// "it minted, just as the wrong principal" failure that is very hard to see.
type ManagedIdentityCreds struct {
	ClientID string
}

// Validate reports whether there is an identity to assume.
func (c ManagedIdentityCreds) Validate() error {
	if strings.TrimSpace(c.ClientID) == "" {
		return fmt.Errorf("%w: managed identity requires client_id (the user-assigned identity's "+
			"client id; an empty value would silently select the system-assigned identity instead)",
			ErrInvalidCreds)
	}
	return nil
}

// Fingerprint keys a cache. Namespaced so a managed-identity client id can
// never collide with a federated one -- the two credential types carry the same
// single field and nothing else, so without the namespace they would hash
// identically and a token minted for one would be served for the other.
func (c ManagedIdentityCreds) Fingerprint() string {
	sum := sha256.Sum256([]byte("entra_managed_identity\x00" + c.ClientID))
	return hex.EncodeToString(sum[:])
}

// ManagedIdentityCredentialFactory builds the credential for a client id.
type ManagedIdentityCredentialFactory func(clientID string) (FederatedCredential, error)

// defaultManagedIdentityCredentialFactory is the real one.
//
// Only a user-assigned identity selected by CLIENT id is plumbed. azidentity
// also accepts ResourceID and ObjectID, and the system-assigned identity via an
// absent ID; none is exposed, because each is a distinct principal and the
// registry's row carries exactly one identifier field. Adding one later is
// additive.
// managedIdentityCredentialOptions builds the SDK options for a client id.
//
// A separate function so the identity SELECTION can be asserted directly. The
// credential the SDK returns exposes nothing about which identity it will ask
// for, and the dangerous mutation here is silent: dropping the ID entirely
// yields a perfectly working credential for the SYSTEM-assigned identity --
// a different principal, with different Azure DevOps grants, that mints
// successfully. Nothing downstream would notice.
func managedIdentityCredentialOptions(clientID string) *azidentity.ManagedIdentityCredentialOptions {
	return &azidentity.ManagedIdentityCredentialOptions{
		ID: azidentity.ClientID(clientID),
	}
}

func defaultManagedIdentityCredentialFactory(clientID string) (FederatedCredential, error) {
	cred, err := azidentity.NewManagedIdentityCredential(managedIdentityCredentialOptions(clientID))
	if err != nil {
		// Untyped nil, for the same reason as the federated and certificate
		// factories: a nil concrete pointer stored in an interface is a NON-nil
		// interface value, so a caller checking the credential instead of the
		// error would panic on first use.
		return nil, err
	}
	return cred, nil
}

// MintManagedIdentity asks the platform's identity endpoint for an Azure DevOps
// access token. It returns the same Token shape as the other mints, so a
// caller's caching is identical whichever credential type a record carries.
func (m *Minter) MintManagedIdentity(ctx context.Context, creds ManagedIdentityCreds) (Token, error) {
	if err := creds.Validate(); err != nil {
		return Token{}, err
	}

	cred, err := m.managedIdentityFactory(strings.TrimSpace(creds.ClientID))
	if err != nil {
		return Token{}, fmt.Errorf(
			"appcreds: could not build a managed identity credential for client_id %s "+
				"(managed identity works only on Azure compute -- an Azure VM or VMSS, AKS, "+
				"Container Apps or App Service -- where the platform provides an identity "+
				"endpoint): %w", creds.ClientID, err)
	}

	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{AzureDevOpsResourceID + "/.default"},
	})
	if err != nil {
		// The two failures an operator must be able to tell apart are "this host
		// has no identity endpoint at all" (wrong platform) and "the endpoint
		// answered and refused" (the identity is not assigned to this compute,
		// or lacks the Azure DevOps grant). The SDK reports the first as a
		// transport failure after its own retries, which off Azure means a wait
		// on a link-local address that goes nowhere.
		return Token{}, fmt.Errorf(
			"appcreds: mint managed identity Azure DevOps token for client_id %s "+
				"(if this host is not Azure compute there is no identity endpoint to answer; "+
				"if it is, check that the user-assigned identity is attached to this resource "+
				"and granted access to Azure DevOps): %w", creds.ClientID, err)
	}
	if tok.Token == "" {
		return Token{}, errors.New("appcreds: managed identity token exchange returned an empty token")
	}
	return Token{AccessToken: tok.Token, ExpiresAt: tok.ExpiresOn}, nil
}

// Compile-time proof that the SDK's credential satisfies the narrow interface.
var _ FederatedCredential = (*azidentity.ManagedIdentityCredential)(nil)
