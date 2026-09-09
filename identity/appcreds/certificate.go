// certificate.go mints Azure DevOps access tokens from a Microsoft Entra app
// registration proved by a CERTIFICATE: the app signs a client assertion with
// a private key it holds, and Entra exchanges that assertion for a token. No
// secret crosses the wire -- only the signature does.
//
// This is the credential Microsoft points to when a deployment cannot federate
// (see federated.go). Against a client secret it wins twice: the secret is sent
// on every token request while the key only ever signs locally, and the
// secret's lifetime is capped by Entra at 24 months while a certificate's is
// the operator's to choose.
package appcreds

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// CertificateCreds is an Entra app registration proved by a certificate.
//
// CertificatePEM is a PEM bundle holding the certificate (or chain) AND its
// UNENCRYPTED private key. The key is not a separate field because the two are
// only meaningful together: Entra identifies the key by the certificate's
// thumbprint, so a key without its certificate cannot name itself, and a
// certificate without its key cannot sign.
type CertificateCreds struct {
	TenantID       string
	ClientID       string
	CertificatePEM string
}

// Validate reports whether the exchange has everything it needs. It checks
// presence only; ValidCertificateBundle parses the material, and callers should
// run that at the point a bundle is accepted from a user rather than at every
// mint, so a bad upload is a 400 on the request that supplied it.
func (c CertificateCreds) Validate() error {
	var missing []string
	if strings.TrimSpace(c.TenantID) == "" {
		missing = append(missing, "tenant_id")
	}
	if strings.TrimSpace(c.ClientID) == "" {
		missing = append(missing, "client_id")
	}
	if strings.TrimSpace(c.CertificatePEM) == "" {
		missing = append(missing, "certificate")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: entra certificate auth requires %s",
			ErrInvalidCreds, strings.Join(missing, ", "))
	}
	return nil
}

// Fingerprint keys a cache. Folds in the whole bundle so rotating the
// certificate -- the operation this credential type exists to make routine --
// invalidates the cached token even when tenant and client are unchanged.
func (c CertificateCreds) Fingerprint() string {
	sum := sha256.Sum256([]byte("entra_certificate\x00" + c.TenantID + "\x00" + c.ClientID + "\x00" + c.CertificatePEM))
	return hex.EncodeToString(sum[:])
}

// CertificateCredentialFactory builds the credential that signs and exchanges
// the assertion. The authority host is passed explicitly so a sovereign-cloud
// login endpoint configured through WithEntraLoginBaseURL is honoured here
// exactly as MintEntra honours it; the SDK's default is the public cloud.
type CertificateCredentialFactory func(
	authorityHost, tenantID, clientID string,
	certs []*x509.Certificate, key crypto.PrivateKey,
) (FederatedCredential, error)

// defaultCertificateCredentialFactory is the real one.
// certificateCredentialOptions builds the SDK options for an authority host.
// A separate function so the sovereign-cloud mapping can be asserted directly:
// the resulting credential exposes nothing about which authority it will use,
// so the only place to check that a configured login host reaches the SDK is
// here, before the SDK swallows it.
func certificateCredentialOptions(authorityHost string) *azidentity.ClientCertificateCredentialOptions {
	opts := &azidentity.ClientCertificateCredentialOptions{
		// Entra verifies the assertion against the certificate registered on
		// the app, matched by thumbprint. Sending the chain lets Entra accept a
		// certificate it has only seen via its issuer, which is how a rotated
		// certificate from the same CA keeps working without re-registration.
		SendCertificateChain: true,
	}
	if authorityHost != "" && authorityHost != DefaultEntraLoginBaseURL {
		opts.ClientOptions.Cloud = cloud.Configuration{ActiveDirectoryAuthorityHost: authorityHost}
	}
	return opts
}

func defaultCertificateCredentialFactory(
	authorityHost, tenantID, clientID string,
	certs []*x509.Certificate, key crypto.PrivateKey,
) (FederatedCredential, error) {
	cred, err := azidentity.NewClientCertificateCredential(tenantID, clientID, certs, key,
		certificateCredentialOptions(authorityHost))
	if err != nil {
		// Untyped nil, for the same reason as the federated factory: a nil
		// concrete pointer in an interface is a non-nil interface value.
		return nil, err
	}
	return cred, nil
}

// ParseCertificateBundle parses a PEM bundle into the certificate(s) and the
// private key MintCertificate needs.
//
// Exported so a caller can validate a bundle at the point it is accepted -- and
// so the check performed at upload is, by construction, the one performed at
// mint. Returns an error that names what is wrong: no certificate, no key, or
// a key the SDK cannot read (it does not decrypt PEM-encrypted keys).
func ParseCertificateBundle(bundlePEM string) ([]*x509.Certificate, crypto.PrivateKey, error) {
	if strings.TrimSpace(bundlePEM) == "" {
		return nil, nil, errors.New("appcreds: certificate bundle is empty")
	}
	certs, key, err := azidentity.ParseCertificates([]byte(bundlePEM), nil)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"appcreds: certificate bundle could not be parsed (it must be PEM containing the "+
				"certificate and an unencrypted private key): %w", err)
	}
	// Both of these are redundant with the SDK today: ParseCertificates already
	// returns "found no certificate" / "found no private key" for a partial
	// bundle, so mutating either away survives. They are kept because the SDK's
	// behaviour on partial input is not a documented contract, and the cost of
	// it changing would be a credential built from half a bundle that fails at
	// the first mint instead of at upload.
	if len(certs) == 0 {
		return nil, nil, errors.New("appcreds: certificate bundle contains no certificate")
	}
	if key == nil {
		return nil, nil, errors.New("appcreds: certificate bundle contains no private key")
	}
	return certs, key, nil
}

// ValidCertificateBundle reports whether bundlePEM parses, as an error naming
// the problem. The certificate-credential counterpart of ValidRSAPrivateKey.
func ValidCertificateBundle(bundlePEM string) error {
	_, _, err := ParseCertificateBundle(bundlePEM)
	return err
}

// MintCertificate signs a client assertion with the bundle's private key and
// exchanges it for an Azure DevOps access token. Returns the same Token shape
// as the other mints, so a caller's caching is identical whichever credential
// type a record carries.
func (m *Minter) MintCertificate(ctx context.Context, creds CertificateCreds) (Token, error) {
	if err := creds.Validate(); err != nil {
		return Token{}, err
	}
	certs, key, err := ParseCertificateBundle(creds.CertificatePEM)
	if err != nil {
		return Token{}, fmt.Errorf("%w: %s", ErrInvalidCreds, err.Error())
	}

	cred, err := m.certificateFactory(m.entraLoginBaseURL,
		strings.TrimSpace(creds.TenantID), strings.TrimSpace(creds.ClientID), certs, key)
	if err != nil {
		return Token{}, fmt.Errorf("appcreds: could not build a certificate credential for client_id %s: %w",
			creds.ClientID, err)
	}

	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{AzureDevOpsResourceID + "/.default"},
	})
	if err != nil {
		return Token{}, fmt.Errorf("appcreds: mint certificate Azure DevOps token: %w", err)
	}
	if tok.Token == "" {
		return Token{}, errors.New("appcreds: certificate token exchange returned an empty token")
	}
	return Token{AccessToken: tok.Token, ExpiresAt: tok.ExpiresOn}, nil
}

// Compile-time proof that the SDK's credential satisfies the narrow interface.
var _ FederatedCredential = (*azidentity.ClientCertificateCredential)(nil)
var _ = azcore.AccessToken{}
