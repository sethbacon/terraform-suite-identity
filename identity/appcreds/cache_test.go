package appcreds

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// A cache is shared across credential TYPES, so two different credentials must
// never hash alike. The dangerous case is the one field they share: a client id.
// Without the namespace prefix, a federated identity and an Entra app with an
// empty tenant and secret would key the same entry, and a token minted for one
// would be served for the other.
func TestFingerprint_NoCollisionAcrossCredentialTypes(t *testing.T) {
	seen := map[string]string{}
	add := func(label string, c Creds) {
		t.Helper()
		fp := c.Fingerprint()
		if prev, dup := seen[fp]; dup {
			t.Errorf("%s and %s share a fingerprint; one credential's token would be served for the other", label, prev)
		}
		seen[fp] = label
	}

	add("entra(t,c,s)", EntraCreds{TenantID: "t", ClientID: "c", ClientSecret: "s"})
	add("entra(empty tenant+secret, client c)", EntraCreds{ClientID: "c"})
	add("federated(c)", FederatedCreds{ClientID: "c"})
	add("githubapp(c,,)", GitHubAppCreds{AppID: "c"})
	add("githubapp(1,2,k)", GitHubAppCreds{AppID: "1", InstallationID: "2", PrivateKeyPEM: "k"})

	// The case the type namespace actually prevents, and the reason separators
	// alone are not enough: a federated client id that CONTAINS the separator
	// byte reproduces an EntraCreds' exact hash input field-for-field. Verified
	// by construction -- unnamespaced, these two hash identically.
	add("entra(x,y,z)", EntraCreds{TenantID: "x", ClientID: "y", ClientSecret: "z"})
	add("federated(x\x00y\x00z)", FederatedCreds{ClientID: "x\x00y\x00z"})

	// Same shape for the GitHub App triple.
	add("githubapp(p,q,r)", GitHubAppCreds{AppID: "p", InstallationID: "q", PrivateKeyPEM: "r"})
	add("federated(p\x00q\x00r)", FederatedCreds{ClientID: "p\x00q\x00r"})
}

// The NUL separators are what stop two different field splits from hashing
// alike. Without them "ab"+"c" and "a"+"bc" concatenate to the same string.
func TestFingerprint_FieldBoundariesAreNotAmbiguous(t *testing.T) {
	a := EntraCreds{TenantID: "ab", ClientID: "c", ClientSecret: "s"}
	b := EntraCreds{TenantID: "a", ClientID: "bc", ClientSecret: "s"}
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("two different credentials hash alike; the field boundary is ambiguous")
	}

	g1 := GitHubAppCreds{AppID: "12", InstallationID: "3", PrivateKeyPEM: "k"}
	g2 := GitHubAppCreds{AppID: "1", InstallationID: "23", PrivateKeyPEM: "k"}
	if g1.Fingerprint() == g2.Fingerprint() {
		t.Error("two different GitHub App credentials hash alike")
	}
}

// Rotation must be self-invalidating: change any field and the credentials hash
// to a key nothing was ever stored under.
func TestFingerprint_ChangesWithEveryField(t *testing.T) {
	base := EntraCreds{TenantID: "t", ClientID: "c", ClientSecret: "s"}
	for _, rotated := range []EntraCreds{
		{TenantID: "t2", ClientID: "c", ClientSecret: "s"},
		{TenantID: "t", ClientID: "c2", ClientSecret: "s"},
		{TenantID: "t", ClientID: "c", ClientSecret: "s2"},
	} {
		if base.Fingerprint() == rotated.Fingerprint() {
			t.Errorf("%+v hashes the same as the credential it replaced; the old token would still be served", rotated)
		}
	}

	// The private key is the field a GitHub App rotation actually changes --
	// app and installation ids stay put.
	k1 := GitHubAppCreds{AppID: "1", InstallationID: "2", PrivateKeyPEM: "old"}
	k2 := GitHubAppCreds{AppID: "1", InstallationID: "2", PrivateKeyPEM: "new"}
	if k1.Fingerprint() == k2.Fingerprint() {
		t.Error("rotating only the private key did not change the fingerprint")
	}

	if (FederatedCreds{ClientID: "a"}).Fingerprint() == (FederatedCreds{ClientID: "b"}).Fingerprint() {
		t.Error("two federated identities hash alike")
	}
}

func TestToken_Expired(t *testing.T) {
	now := testNow
	cases := []struct {
		name   string
		tok    Token
		margin time.Duration
		want   bool
	}{
		{"fresh", Token{AccessToken: "t", ExpiresAt: now.Add(time.Hour)}, time.Minute, false},
		{"inside the margin", Token{AccessToken: "t", ExpiresAt: now.Add(30 * time.Second)}, time.Minute, true},
		{"exactly at the margin", Token{AccessToken: "t", ExpiresAt: now.Add(time.Minute)}, time.Minute, true},
		{"already past", Token{AccessToken: "t", ExpiresAt: now.Add(-time.Second)}, 0, true},
		{"empty token", Token{ExpiresAt: now.Add(time.Hour)}, time.Minute, true},
		// A token with no expiry is treated as spent, not immortal. The
		// opposite reading serves a dead token forever.
		{"no expiry reported", Token{AccessToken: "t"}, time.Minute, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.tok.Expired(now, tc.margin); got != tc.want {
				t.Errorf("Expired = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCache_RoundTripAndExpiry(t *testing.T) {
	creds := EntraCreds{TenantID: "t", ClientID: "c", ClientSecret: "s"}
	c := NewCache(time.Minute)
	c.now = fixedClock(testNow)

	if _, ok := c.Get(creds); ok {
		t.Error("an empty cache returned a token")
	}

	c.Put(creds, Token{AccessToken: "tok", ExpiresAt: testNow.Add(time.Hour)})
	got, ok := c.Get(creds)
	if !ok || got.AccessToken != "tok" {
		t.Fatalf("Get = (%+v, %v), want the stored token", got, ok)
	}

	// A different credential must not read another's entry.
	if _, ok := c.Get(EntraCreds{TenantID: "t", ClientID: "c", ClientSecret: "rotated"}); ok {
		t.Error("rotated credentials read the old credential's token")
	}

	// Inside the refresh margin the entry is not served, AND is dropped so an
	// unused credential cannot pin its last token forever.
	c.Put(creds, Token{AccessToken: "stale", ExpiresAt: testNow.Add(30 * time.Second)})
	if _, ok := c.Get(creds); ok {
		t.Error("a token inside the refresh margin was served")
	}
	if c.Len() != 0 {
		t.Errorf("expired entry was left in the map (len=%d)", c.Len())
	}
}

// Caching an empty token would turn one failed mint into a run of them.
func TestCache_DoesNotStoreAnEmptyToken(t *testing.T) {
	c := NewCache(time.Minute)
	creds := FederatedCreds{ClientID: "c"}
	c.Put(creds, Token{ExpiresAt: testNow.Add(time.Hour)})
	if c.Len() != 0 {
		t.Error("an empty token was cached")
	}
}

func TestCache_Evict(t *testing.T) {
	c := NewCache(time.Minute)
	c.now = fixedClock(testNow)
	old := EntraCreds{TenantID: "t", ClientID: "c", ClientSecret: "old"}
	c.Put(old, Token{AccessToken: "tok", ExpiresAt: testNow.Add(time.Hour)})

	// The route shape this exists for: capture the OLD fingerprint before
	// overwriting the record, then evict it.
	key := old.Fingerprint()
	c.EvictKey(key)
	if _, ok := c.Get(old); ok {
		t.Error("the evicted credential still serves a token")
	}

	c.Put(old, Token{AccessToken: "tok", ExpiresAt: testNow.Add(time.Hour)})
	c.Evict(old)
	if c.Len() != 0 {
		t.Error("Evict did not remove the entry")
	}

	// Neither form may panic or clear the map wholesale on a miss.
	c.Put(old, Token{AccessToken: "tok", ExpiresAt: testNow.Add(time.Hour)})
	c.EvictKey("")
	c.Evict(nil)
	c.EvictKey("no-such-key")
	if c.Len() != 1 {
		t.Errorf("a no-op evict changed the cache (len=%d, want 1)", c.Len())
	}

	c.Reset()
	if c.Len() != 0 {
		t.Error("Reset left entries behind")
	}
}

func TestCache_ZeroValueAndMargins(t *testing.T) {
	// The zero value is usable: Put must allocate rather than panic on a nil map.
	var c Cache
	creds := FederatedCreds{ClientID: "c"}
	c.Put(creds, Token{AccessToken: "tok", ExpiresAt: time.Now().Add(time.Hour)})
	if _, ok := c.Get(creds); !ok {
		t.Error("the zero-value cache did not store a token")
	}
	if _, ok := c.Get(nil); ok {
		t.Error("Get(nil) returned a token")
	}
	c.Put(nil, Token{AccessToken: "x", ExpiresAt: time.Now().Add(time.Hour)})

	// A zero margin means the default, so a caller who never thought about it
	// still gets a safety window rather than serving up to the last instant.
	if got := NewCache(0).refreshMargin(); got != DefaultRefreshMargin {
		t.Errorf("zero margin = %v, want DefaultRefreshMargin", got)
	}
	// Negative is the explicit opt-out.
	if got := NewCache(-1).refreshMargin(); got != 0 {
		t.Errorf("negative margin = %v, want 0", got)
	}
}

func TestCache_ConcurrentUse(t *testing.T) {
	c := NewCache(time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			creds := FederatedCreds{ClientID: string(rune('a' + i%5))}
			c.Put(creds, Token{AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour)})
			c.Get(creds)
			c.Evict(creds)
			c.Len()
		}(i)
	}
	wg.Wait()
}

func TestCachedMinter_ReadsThroughAndMintsOnce(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"ado-token","expires_in":3600}`))
	}))
	defer srv.Close()

	cache := NewCache(time.Minute)
	cache.now = fixedClock(testNow)
	cm := CachedMinter{
		Minter: newTestMinter(t, WithEntraLoginBaseURL(srv.URL), WithClock(fixedClock(testNow))),
		Cache:  cache,
	}
	creds := EntraCreds{TenantID: "t", ClientID: "c", ClientSecret: "s"}

	for i := 0; i < 3; i++ {
		tok, err := cm.Entra(context.Background(), creds)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if tok.AccessToken != "ado-token" {
			t.Fatalf("call %d: token = %q", i, tok.AccessToken)
		}
	}
	if calls != 1 {
		t.Errorf("token endpoint called %d times across 3 reads, want 1", calls)
	}

	// Rotating the secret must not serve the cached token.
	if _, err := cm.Entra(context.Background(), EntraCreds{TenantID: "t", ClientID: "c", ClientSecret: "rotated"}); err != nil {
		t.Fatalf("rotated: %v", err)
	}
	if calls != 2 {
		t.Errorf("rotated credentials served a cached token (calls=%d, want 2)", calls)
	}
}

func TestCachedMinter_FederatedAndGitHubAppUseTheCache(t *testing.T) {
	cred := &fakeFederatedCredential{token: azcore.AccessToken{Token: "fed", ExpiresOn: testNow.Add(time.Hour)}}
	cache := NewCache(time.Minute)
	cache.now = fixedClock(testNow)
	cm := CachedMinter{
		Minter: newTestMinter(t, WithFederatedCredentialFactory(fakeFactory(cred, nil)), WithClock(fixedClock(testNow))),
		Cache:  cache,
	}
	for i := 0; i < 3; i++ {
		if _, err := cm.Federated(context.Background(), FederatedCreds{ClientID: "c"}); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if cred.calls != 1 {
		t.Errorf("federated exchange ran %d times across 3 reads, want 1", cred.calls)
	}

	_, keyPEM := testRSAKey(t)
	var ghCalls int
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ghCalls++
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"ghs","expires_at":"2027-01-01T00:00:00Z"}`))
	}))
	defer ghSrv.Close()

	ghCache := NewCache(time.Minute)
	ghCache.now = fixedClock(testNow)
	ghcm := CachedMinter{
		Minter: newTestMinter(t, WithGitHubAPIBaseURL(ghSrv.URL), WithClock(fixedClock(testNow))),
		Cache:  ghCache,
	}
	ghCreds := GitHubAppCreds{AppID: "1", InstallationID: "2", PrivateKeyPEM: keyPEM}
	for i := 0; i < 3; i++ {
		if _, err := ghcm.GitHubApp(context.Background(), ghCreds); err != nil {
			t.Fatalf("gh call %d: %v", i, err)
		}
	}
	if ghCalls != 1 {
		t.Errorf("installation token endpoint called %d times across 3 reads, want 1", ghCalls)
	}
}

// A failed mint must not be cached, or one upstream blip becomes a sticky
// failure for the whole refresh window.
func TestCachedMinter_DoesNotCacheAFailure(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cm := CachedMinter{Minter: newTestMinter(t, WithEntraLoginBaseURL(srv.URL)), Cache: NewCache(time.Minute)}
	creds := EntraCreds{TenantID: "t", ClientID: "c", ClientSecret: "s"}
	for i := 0; i < 2; i++ {
		if _, err := cm.Entra(context.Background(), creds); err == nil {
			t.Fatalf("call %d succeeded against a failing endpoint", i)
		}
	}
	if calls != 2 {
		t.Errorf("endpoint called %d times, want 2 -- a failure was cached", calls)
	}
	if cm.Cache.Len() != 0 {
		t.Error("a failed mint left an entry in the cache")
	}
}

func TestCachedMinter_WithoutACacheStillMints(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
	}))
	defer srv.Close()

	cm := CachedMinter{Minter: newTestMinter(t, WithEntraLoginBaseURL(srv.URL))}
	for i := 0; i < 2; i++ {
		if _, err := cm.Entra(context.Background(), EntraCreds{TenantID: "t", ClientID: "c", ClientSecret: "s"}); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2 -- without a cache every call mints", calls)
	}
}

func TestCachedMinter_NoMinterIsAnErrorNotAPanic(t *testing.T) {
	cm := CachedMinter{Cache: NewCache(time.Minute)}
	_, err := cm.Entra(context.Background(), EntraCreds{TenantID: "t", ClientID: "c", ClientSecret: "s"})
	if err == nil {
		t.Fatal("a CachedMinter with no Minter minted")
	}
	if !strings.Contains(err.Error(), "no Minter") {
		t.Errorf("error %v does not say what is missing", err)
	}
}

// Invalid credentials are rejected before the cache is touched, so a validation
// failure can never be mistaken for a cache miss and retried against the network.
func TestCachedMinter_ValidatesBeforeReachingTheCache(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer srv.Close()

	cm := CachedMinter{Minter: newTestMinter(t, WithEntraLoginBaseURL(srv.URL)), Cache: NewCache(time.Minute)}
	if _, err := cm.Entra(context.Background(), EntraCreds{ClientID: "c"}); !errors.Is(err, ErrInvalidCreds) {
		t.Errorf("error %v is not ErrInvalidCreds", err)
	}
	if calls != 0 || cm.Cache.Len() != 0 {
		t.Errorf("invalid credentials reached the network (%d calls) or the cache (%d entries)", calls, cm.Cache.Len())
	}
}
