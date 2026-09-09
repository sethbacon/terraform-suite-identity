package appcreds

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// selfSignedBundle generates a real certificate and key at test time and
// returns them as the PEM bundle an operator would upload. Generated rather
// than a checked-in fixture so the parse path is exercised against genuine
// material every run, and so no static file can drift from what the SDK
// accepts.
func selfSignedBundle(t *testing.T, key crypto.Signer) (bundle string, cert *x509.Certificate) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "registry-entra-app"},
		NotBefore:    testNow.Add(-time.Hour),
		NotAfter:     testNow.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	bundle = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return bundle, cert
}

func rsaSigner(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return k
}

// fakeCertificateFactory records everything the mint passed to it -- which is
// the whole assertion this credential type makes: the right tenant, the right
// client, THIS certificate, THIS key, and the configured authority.
type fakeCertificateFactory struct {
	cred          *fakeFederatedCredential
	buildErr      error
	authorityHost string
	tenantID      string
	clientID      string
	certs         []*x509.Certificate
	key           crypto.PrivateKey
	calls         int
}

func (f *fakeCertificateFactory) factory() CertificateCredentialFactory {
	return func(authorityHost, tenantID, clientID string, certs []*x509.Certificate, key crypto.PrivateKey) (FederatedCredential, error) {
		f.calls++
		f.authorityHost, f.tenantID, f.clientID, f.certs, f.key = authorityHost, tenantID, clientID, certs, key
		if f.buildErr != nil {
			return nil, f.buildErr
		}
		return f.cred, nil
	}
}

func TestMintCertificate_Success(t *testing.T) {
	signer := rsaSigner(t)
	bundle, cert := selfSignedBundle(t, signer)
	expiry := testNow.Add(time.Hour)
	fake := &fakeCertificateFactory{cred: &fakeFederatedCredential{
		token: azcore.AccessToken{Token: "cert-token", ExpiresOn: expiry}}}
	m := New(WithCertificateCredentialFactory(fake.factory()), WithClock(fixedClock(testNow)))

	tok, err := m.MintCertificate(context.Background(), CertificateCreds{
		TenantID: "  tenant-1  ", ClientID: " client-1 ", CertificatePEM: bundle,
	})
	if err != nil {
		t.Fatalf("MintCertificate: %v", err)
	}
	if tok.AccessToken != "cert-token" || !tok.ExpiresAt.Equal(expiry) {
		t.Errorf("token = %+v, want cert-token expiring %v", tok, expiry)
	}
	if fake.tenantID != "tenant-1" || fake.clientID != "client-1" {
		t.Errorf("credential built for (%q, %q) -- whitespace not trimmed", fake.tenantID, fake.clientID)
	}
	// The certificate handed to the SDK must be the one from the bundle, and the
	// key must be the one that signed it. A parse that returned the wrong pair
	// would produce an assertion Entra cannot verify, failing far from here.
	if len(fake.certs) != 1 || !fake.certs[0].Equal(cert) {
		t.Errorf("credential built with %d certs, not the bundle's own", len(fake.certs))
	}
	if k, ok := fake.key.(*rsa.PrivateKey); !ok || !k.PublicKey.Equal(signer.Public()) {
		t.Errorf("credential built with a key that is not the bundle's own (%T)", fake.key)
	}
	if fake.cred.calls != 1 {
		t.Errorf("token exchanged %d times, want 1", fake.cred.calls)
	}
	if len(fake.cred.scopes) != 1 || fake.cred.scopes[0] != AzureDevOpsResourceID+"/.default" {
		t.Errorf("scopes = %v, want the Azure DevOps resource id", fake.cred.scopes)
	}
}

// A sovereign-cloud login host configured for the client-secret path must
// reach the certificate path too, or the assertion goes to the public cloud's
// authority and is rejected there.
func TestMintCertificate_HonoursTheConfiguredAuthority(t *testing.T) {
	bundle, _ := selfSignedBundle(t, rsaSigner(t))
	fake := &fakeCertificateFactory{cred: &fakeFederatedCredential{token: azcore.AccessToken{Token: "t", ExpiresOn: testNow.Add(time.Hour)}}}
	m := New(
		WithCertificateCredentialFactory(fake.factory()),
		WithEntraLoginBaseURL("https://login.microsoftonline.us"),
	)
	if _, err := m.MintCertificate(context.Background(), CertificateCreds{
		TenantID: "t", ClientID: "c", CertificatePEM: bundle,
	}); err != nil {
		t.Fatalf("MintCertificate: %v", err)
	}
	if fake.authorityHost != "https://login.microsoftonline.us" {
		t.Errorf("authority = %q, want the configured sovereign host", fake.authorityHost)
	}
}

// ECDSA keys are a supported x509 key type and a plausible operator choice.
func TestMintCertificate_AcceptsAnECDSAKey(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	bundle, _ := selfSignedBundle(t, ec)
	fake := &fakeCertificateFactory{cred: &fakeFederatedCredential{token: azcore.AccessToken{Token: "t", ExpiresOn: testNow.Add(time.Hour)}}}
	m := New(WithCertificateCredentialFactory(fake.factory()))
	if _, err := m.MintCertificate(context.Background(), CertificateCreds{
		TenantID: "t", ClientID: "c", CertificatePEM: bundle,
	}); err != nil {
		t.Fatalf("an ECDSA bundle was rejected: %v", err)
	}
	if _, ok := fake.key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("key handed to the SDK is %T, want *ecdsa.PrivateKey", fake.key)
	}
}

// A certificate mint must never touch the client-secret endpoint: there is no
// secret to send, and reaching it would mean the wrong arm ran.
func TestMintCertificate_NeverCallsTheClientSecretEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the client-credentials endpoint was called for a certificate mint")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	bundle, _ := selfSignedBundle(t, rsaSigner(t))
	fake := &fakeCertificateFactory{cred: &fakeFederatedCredential{token: azcore.AccessToken{Token: "t", ExpiresOn: testNow.Add(time.Hour)}}}
	m := New(WithEntraLoginBaseURL(srv.URL), WithCertificateCredentialFactory(fake.factory()))
	if _, err := m.MintCertificate(context.Background(), CertificateCreds{
		TenantID: "t", ClientID: "c", CertificatePEM: bundle,
	}); err != nil {
		t.Fatalf("MintCertificate: %v", err)
	}
}

func TestMintCertificate_Failures(t *testing.T) {
	bundle, _ := selfSignedBundle(t, rsaSigner(t))

	t.Run("missing fields never reach the factory", func(t *testing.T) {
		fake := &fakeCertificateFactory{cred: &fakeFederatedCredential{}}
		m := New(WithCertificateCredentialFactory(fake.factory()))
		for _, c := range []CertificateCreds{
			{ClientID: "c", CertificatePEM: bundle},
			{TenantID: "t", CertificatePEM: bundle},
			{TenantID: "t", ClientID: "c"},
			{},
		} {
			_, err := m.MintCertificate(context.Background(), c)
			if !errors.Is(err, ErrInvalidCreds) {
				t.Errorf("%+v: error %v is not ErrInvalidCreds", c, err)
			}
		}
		if fake.calls != 0 {
			t.Errorf("factory called %d times with invalid credentials, want 0", fake.calls)
		}
	})

	t.Run("an unparseable bundle is ErrInvalidCreds, not an upstream failure", func(t *testing.T) {
		// A 400 for the caller, not a 502: nothing was sent anywhere.
		fake := &fakeCertificateFactory{cred: &fakeFederatedCredential{}}
		m := New(WithCertificateCredentialFactory(fake.factory()))
		_, err := m.MintCertificate(context.Background(), CertificateCreds{
			TenantID: "t", ClientID: "c", CertificatePEM: "not a pem bundle",
		})
		if !errors.Is(err, ErrInvalidCreds) {
			t.Errorf("error %v is not ErrInvalidCreds", err)
		}
		if fake.calls != 0 {
			t.Errorf("factory called with garbage material")
		}
	})

	t.Run("the credential cannot be built", func(t *testing.T) {
		fake := &fakeCertificateFactory{buildErr: errors.New("key does not match certificate")}
		m := New(WithCertificateCredentialFactory(fake.factory()))
		_, err := m.MintCertificate(context.Background(), CertificateCreds{TenantID: "t", ClientID: "c", CertificatePEM: bundle})
		if err == nil || !strings.Contains(err.Error(), "key does not match certificate") {
			t.Errorf("the build error was swallowed: %v", err)
		}
	})

	t.Run("the exchange is rejected", func(t *testing.T) {
		fake := &fakeCertificateFactory{cred: &fakeFederatedCredential{err: errors.New("AADSTS700027: certificate not registered")}}
		m := New(WithCertificateCredentialFactory(fake.factory()))
		_, err := m.MintCertificate(context.Background(), CertificateCreds{TenantID: "t", ClientID: "c", CertificatePEM: bundle})
		if err == nil || !strings.Contains(err.Error(), "AADSTS700027") {
			t.Errorf("the upstream reason was dropped: %v", err)
		}
	})

	t.Run("an empty token reported as success", func(t *testing.T) {
		fake := &fakeCertificateFactory{cred: &fakeFederatedCredential{token: azcore.AccessToken{ExpiresOn: testNow.Add(time.Hour)}}}
		m := New(WithCertificateCredentialFactory(fake.factory()))
		if _, err := m.MintCertificate(context.Background(), CertificateCreds{TenantID: "t", ClientID: "c", CertificatePEM: bundle}); err == nil {
			t.Fatal("an empty token was accepted")
		}
	})
}

func TestParseCertificateBundle(t *testing.T) {
	signer := rsaSigner(t)
	bundle, cert := selfSignedBundle(t, signer)

	t.Run("a complete bundle", func(t *testing.T) {
		certs, key, err := ParseCertificateBundle(bundle)
		if err != nil {
			t.Fatalf("ParseCertificateBundle: %v", err)
		}
		if len(certs) != 1 || !certs[0].Equal(cert) || key == nil {
			t.Errorf("parsed (%d certs, key %T), want the bundle's own", len(certs), key)
		}
		if err := ValidCertificateBundle(bundle); err != nil {
			t.Errorf("ValidCertificateBundle rejected a good bundle: %v", err)
		}
	})

	// Each failure names what is missing, because the operator fixing an upload
	// needs to know whether they pasted only the certificate or only the key.
	t.Run("certificate without a key", func(t *testing.T) {
		certOnly := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		err := ValidCertificateBundle(certOnly)
		if err == nil || !strings.Contains(err.Error(), "no private key") {
			t.Errorf("error = %v, want it to name the missing key", err)
		}
	})

	t.Run("key without a certificate", func(t *testing.T) {
		der, _ := x509.MarshalPKCS8PrivateKey(signer)
		keyOnly := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		err := ValidCertificateBundle(keyOnly)
		if err == nil || !strings.Contains(err.Error(), "no certificate") {
			t.Errorf("error = %v, want it to name the missing certificate", err)
		}
	})

	t.Run("garbage and empty", func(t *testing.T) {
		for _, in := range []string{"", "   ", "not pem", "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----"} {
			if err := ValidCertificateBundle(in); err == nil {
				t.Errorf("%q validated", in)
			}
		}
	})
}

func TestCertificateCreds_FingerprintChangesWithTheCertificate(t *testing.T) {
	// Rotation is the operation this credential exists to make routine. The
	// cached token must not survive it even though tenant and client do not
	// change.
	b1, _ := selfSignedBundle(t, rsaSigner(t))
	b2, _ := selfSignedBundle(t, rsaSigner(t))
	a := CertificateCreds{TenantID: "t", ClientID: "c", CertificatePEM: b1}
	b := CertificateCreds{TenantID: "t", ClientID: "c", CertificatePEM: b2}
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("rotating the certificate did not change the fingerprint; the old token would still be served")
	}
	// And it must not collide with the other credential types on shared fields.
	if a.Fingerprint() == (EntraCreds{TenantID: "t", ClientID: "c", ClientSecret: b1}).Fingerprint() {
		t.Error("a certificate credential hashes like a client-secret one")
	}
}

// The DEFAULT factory is the real SDK. A self-signed certificate builds a
// credential fine -- the SDK only validates that the key matches the
// certificate -- so this asserts the wiring and the sovereign-cloud mapping,
// and that a key/certificate mismatch is refused with an untyped nil.
func TestDefaultCertificateCredentialFactory_IsTheRealSDK(t *testing.T) {
	signer := rsaSigner(t)
	bundle, _ := selfSignedBundle(t, signer)
	certs, key, err := ParseCertificateBundle(bundle)
	if err != nil {
		t.Fatalf("ParseCertificateBundle: %v", err)
	}

	cred, err := defaultCertificateCredentialFactory(DefaultEntraLoginBaseURL, "tenant", "client", certs, key)
	if err != nil {
		t.Fatalf("the real factory refused a matching certificate and key: %v", err)
	}
	if cred == nil {
		t.Fatal("the real factory returned no credential and no error")
	}

	// A key that did not sign this certificate. The SDK refuses it, and the
	// factory must hand back an UNTYPED nil alongside the error.
	other := rsaSigner(t)
	cred, err = defaultCertificateCredentialFactory(DefaultEntraLoginBaseURL, "tenant", "client", certs, other)
	if err == nil {
		t.Fatal("a mismatched key was accepted")
	}
	if cred != nil {
		t.Errorf("mismatch returned a non-nil credential (%T) alongside an error", cred)
	}

	// A default Minter reaches this factory, not a stub.
	m := New()
	if m.certificateFactory == nil {
		t.Fatal("default Minter has no certificate factory")
	}
}

// The credential the SDK returns exposes nothing about which authority it will
// use, so the sovereign-cloud mapping is asserted on the options themselves.
// Without this the mapping in the default factory is only ever exercised in a
// sovereign-cloud deployment, where "the assertion went to the public cloud"
// looks like a bad certificate.
func TestCertificateCredentialOptions_AuthorityMapping(t *testing.T) {
	pub := certificateCredentialOptions(DefaultEntraLoginBaseURL)
	if pub.ClientOptions.Cloud.ActiveDirectoryAuthorityHost != "" {
		t.Errorf("public cloud set an explicit authority %q; the SDK default must be left alone",
			pub.ClientOptions.Cloud.ActiveDirectoryAuthorityHost)
	}
	if empty := certificateCredentialOptions(""); empty.ClientOptions.Cloud.ActiveDirectoryAuthorityHost != "" {
		t.Error("an empty host set an explicit authority")
	}

	sov := certificateCredentialOptions("https://login.microsoftonline.us")
	if got := sov.ClientOptions.Cloud.ActiveDirectoryAuthorityHost; got != "https://login.microsoftonline.us" {
		t.Errorf("sovereign authority = %q, want the configured host", got)
	}
	if !sov.SendCertificateChain || !pub.SendCertificateChain {
		t.Error("SendCertificateChain must be set regardless of cloud")
	}
}
