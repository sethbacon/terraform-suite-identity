// aliased_cache_class_test.go covers the class of defect in issue #147: a
// cache that hands out, or takes in, a reference into its own storage, so one
// caller's ordinary local mutation silently rewrites what every other caller
// in the process reads. The default-organization cache is the instance; these
// tests pin the invariant from both sides (nothing escapes, nothing enters)
// and pin the invalidation ordering that keeps a straggling read from undoing
// a write.
package store

import (
	"context"
	"database/sql/driver"
	"reflect"
	"sync"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// orgRowWithIdP builds a default-org row whose nullable IdP fields are
// populated, so a test can reach the *string fields a shallow struct copy
// would still share.
func orgRowWithIdP(displayName, idpType, idpName string) *sqlmock.Rows {
	return sqlmock.NewRows(orgCols).
		AddRow("org-1", "default", displayName, idpType, idpName, time.Now(), time.Now())
}

// TestGetDefaultOrganizationRefillReturnsACopy asserts that the value returned
// by the cache-populating (refill) path is the caller's own.
//
// The refill path runs on the first call and again after every TTL expiry, so
// it is the routine path, not an edge case. OrganizationRepository.Update
// takes exactly the type GetDefaultOrganization returns, which makes
// get-mutate-Update the shape the API invites; if the returned pointer were
// the cached one, that field assignment would publish an uncommitted edit to
// every concurrent reader in the process the instant it executed — before the
// database write, and regardless of whether the write ever succeeded.
func TestGetDefaultOrganizationRefillReturnsACopy(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WithArgs("default").
		WillReturnRows(orgRowWithIdP("Default Org", "oidc", "corp-idp"))

	// First call: cache miss, so this is the refill path.
	org, err := repo.GetDefaultOrganization(context.Background())
	if err != nil {
		t.Fatalf("refill call: unexpected error: %v", err)
	}
	if org == nil {
		t.Fatal("refill call: expected an organization, got nil")
	}

	// The idiomatic get-mutate-Update opening move.
	org.DisplayName = "Mutated By An Unrelated Caller"
	org.Name = "mutated"
	*org.IdpType = "mutated-idp-type"
	*org.IdpName = "mutated-idp-name"

	// Second call: cache hit, no further DB query expected.
	cached, err := repo.GetDefaultOrganization(context.Background())
	if err != nil {
		t.Fatalf("cache-hit call: unexpected error: %v", err)
	}
	if cached == nil {
		t.Fatal("cache-hit call: expected an organization, got nil")
	}

	if cached.DisplayName != "Default Org" {
		t.Errorf("second reader saw DisplayName %q: the first caller's local mutation "+
			"reached the process-wide cache", cached.DisplayName)
	}
	if cached.Name != "default" {
		t.Errorf("second reader saw Name %q, want %q", cached.Name, "default")
	}
	if cached.IdpType == nil || *cached.IdpType != "oidc" {
		t.Errorf("second reader saw IdpType %v: a shallow struct copy still shares the "+
			"*string fields with the cache", deref(cached.IdpType))
	}
	if cached.IdpName == nil || *cached.IdpName != "corp-idp" {
		t.Errorf("second reader saw IdpName %v, want %q", deref(cached.IdpName), "corp-idp")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (an extra DB query occurred): %v", err)
	}
}

// TestGetDefaultOrganizationCacheHitReturnsACopy asserts the same invariant on
// the cache-hit path, which serves the overwhelming majority of calls.
//
// The pointer fields are the point: a struct copy alone leaves IdpType and
// IdpName aimed at the cache's own strings, so a caller writing through either
// pointer would still rewrite what every later reader sees.
func TestGetDefaultOrganizationCacheHitReturnsACopy(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WithArgs("default").
		WillReturnRows(orgRowWithIdP("Default Org", "saml", "corp-saml"))

	// Warm the cache; discard the refill result so only cache hits are in play.
	if _, err := repo.GetDefaultOrganization(context.Background()); err != nil {
		t.Fatalf("warming call: unexpected error: %v", err)
	}

	first, err := repo.GetDefaultOrganization(context.Background())
	if err != nil {
		t.Fatalf("first cache-hit call: unexpected error: %v", err)
	}
	first.DisplayName = "Mutated"
	*first.IdpType = "mutated-idp-type"
	*first.IdpName = "mutated-idp-name"

	second, err := repo.GetDefaultOrganization(context.Background())
	if err != nil {
		t.Fatalf("second cache-hit call: unexpected error: %v", err)
	}

	if second.DisplayName != "Default Org" {
		t.Errorf("second reader saw DisplayName %q, want %q", second.DisplayName, "Default Org")
	}
	if second.IdpType == nil || *second.IdpType != "saml" {
		t.Errorf("second reader saw IdpType %v, want %q: the returned copy still shares "+
			"the cached *string", deref(second.IdpType), "saml")
	}
	if second.IdpName == nil || *second.IdpName != "corp-saml" {
		t.Errorf("second reader saw IdpName %v, want %q", deref(second.IdpName), "corp-saml")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (an extra DB query occurred): %v", err)
	}
}

// TestGetDefaultOrganizationRefillStillPopulatesTheCache is the other
// direction of the invalidation guard: a refill that races nothing must still
// take effect. A guard that discarded every refill would satisfy the
// resurrection test below while quietly turning the cache off, so this asserts
// that an uncontended refill — both the initial one and the one after an
// explicit invalidation — actually populates.
func TestGetDefaultOrganizationRefillStillPopulatesTheCache(t *testing.T) {
	repo, mock := newOrgRepo(t)

	// Exactly two queries are permitted: the initial refill and the refill
	// after the invalidation. A third call must be served from the cache.
	for i := 0; i < 2; i++ {
		mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
			WithArgs("default").
			WillReturnRows(sampleOrgRow())
	}

	if _, err := repo.GetDefaultOrganization(context.Background()); err != nil {
		t.Fatalf("initial refill: unexpected error: %v", err)
	}
	// Served from the cache the initial refill populated.
	if _, err := repo.GetDefaultOrganization(context.Background()); err != nil {
		t.Fatalf("call after initial refill: unexpected error: %v", err)
	}

	repo.InvalidateDefaultOrgCache()

	// Refill #2.
	if _, err := repo.GetDefaultOrganization(context.Background()); err != nil {
		t.Fatalf("refill after invalidation: unexpected error: %v", err)
	}
	// Must be served from the cache refill #2 populated. If refills stopped
	// populating, this issues a third query and sqlmock reports it.
	if _, err := repo.GetDefaultOrganization(context.Background()); err != nil {
		t.Fatalf("call after refill following invalidation: a legitimate refill "+
			"no longer populates the cache: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// gateArgument is a sqlmock argument matcher used as a synchronisation point
// inside a query. sqlmock calls Match while the query is executing, on the
// querying goroutine's stack, which lets a test suspend a read at a precise
// point without sleeping.
type gateArgument struct {
	want     string
	once     sync.Once
	entered  chan struct{}
	release  chan struct{}
	deadline time.Duration
}

func newGateArgument(want string) *gateArgument {
	return &gateArgument{
		want:     want,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
		deadline: 10 * time.Second,
	}
}

// Match blocks the first matching query until release is closed, so the test
// can run an invalidation strictly between "the read started" and "the read
// returned".
func (g *gateArgument) Match(v driver.Value) bool {
	g.once.Do(func() {
		close(g.entered)
		select {
		case <-g.release:
		case <-time.After(g.deadline):
		}
	})
	s, ok := v.(string)
	return ok && s == g.want
}

// TestGetDefaultOrganizationRefillDoesNotResurrectAnInvalidatedEntry pins the
// ordering between an in-flight read and a concurrent invalidation.
//
// The cache exists because the default organization is read on nearly every
// request, so at the moment an administrator renames it there is almost
// always a read already in flight. If that read's pre-rename result were
// allowed to land in the cache after the rename cleared it, the instance that
// performed the write would serve the old organization for another full TTL —
// the one instance whose cache the write was specifically trying to clear.
func TestGetDefaultOrganizationRefillDoesNotResurrectAnInvalidatedEntry(t *testing.T) {
	repo, mock := newOrgRepo(t)

	gate := newGateArgument("default")

	// Query 1: the straggler. It is suspended inside Match until the test
	// releases it, and it returns the PRE-rename row.
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WithArgs(gate).
		WillReturnRows(orgRowWithIdP("Old Display Name", "oidc", "corp-idp"))

	// Query 2: the read that follows. If the straggler's result was correctly
	// discarded, the cache is empty and this query happens.
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WithArgs("default").
		WillReturnRows(orgRowWithIdP("New Display Name", "oidc", "corp-idp"))

	stragglerDone := make(chan struct{})
	go func() {
		defer close(stragglerDone)
		_, _ = repo.GetDefaultOrganization(context.Background())
	}()

	// Wait until the straggler's database read is genuinely under way.
	select {
	case <-gate.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the straggling read never reached the database")
	}

	// The write commits and invalidates while that read is in flight.
	repo.InvalidateDefaultOrgCache()

	close(gate.release)
	<-stragglerDone

	got, err := repo.GetDefaultOrganization(context.Background())
	if err != nil {
		t.Fatalf("post-invalidation read: unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("post-invalidation read: expected an organization, got nil")
	}
	if got.DisplayName != "New Display Name" {
		t.Errorf("post-invalidation read saw DisplayName %q, want %q: the straggling "+
			"read reinstated the pre-invalidation entry", got.DisplayName, "New Display Name")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (the second query never happened, so the "+
			"invalidated entry was served from the cache): %v", err)
	}
}

// TestCloneOrganizationIsIndependentOfItsSource asserts cloneOrganization
// directly, including the nil receiver and nil-pointer-field cases that the
// repository paths above cannot reach.
func TestCloneOrganizationIsIndependentOfItsSource(t *testing.T) {
	if got := cloneOrganization(nil); got != nil {
		t.Errorf("cloneOrganization(nil) = %v, want nil", got)
	}

	idpType := "oidc"
	idpName := "corp-idp"
	src := &models.Organization{
		ID:          "org-1",
		Name:        "default",
		DisplayName: "Default Org",
		IdpType:     &idpType,
		IdpName:     &idpName,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	cp := cloneOrganization(src)
	if cp == src {
		t.Fatal("cloneOrganization returned its argument")
	}
	if !reflect.DeepEqual(*cp, *src) {
		t.Fatalf("clone is not equal to its source:\n got %+v\nwant %+v", *cp, *src)
	}
	if cp.IdpType == src.IdpType {
		t.Error("clone shares the IdpType pointer with its source")
	}
	if cp.IdpName == src.IdpName {
		t.Error("clone shares the IdpName pointer with its source")
	}

	*cp.IdpType = "changed"
	*cp.IdpName = "changed"
	cp.DisplayName = "changed"
	if *src.IdpType != "oidc" || *src.IdpName != "corp-idp" || src.DisplayName != "Default Org" {
		t.Errorf("mutating the clone changed the source: %+v", *src)
	}

	// A nil pointer field must stay nil rather than become a pointer to "".
	bare := cloneOrganization(&models.Organization{ID: "org-2", Name: "other"})
	if bare.IdpType != nil || bare.IdpName != nil {
		t.Errorf("clone of an org with nil IdP fields produced non-nil pointers: %+v", *bare)
	}
}

// TestCloneOrganizationCoversEveryReferenceField fails if a reference-typed
// field is added to models.Organization without cloneOrganization being taught
// to copy it.
//
// This is the guard that keeps "how deep is deep enough" from silently going
// stale: today the answer is "the struct plus the two *string fields", but the
// answer is a property of the model, not a constant, and a new slice, map or
// pointer field would reintroduce the aliasing this file exists to prevent
// without any test here failing.
func TestCloneOrganizationCoversEveryReferenceField(t *testing.T) {
	// The reference-typed fields cloneOrganization explicitly re-allocates.
	cloned := map[string]bool{
		"IdpType": true,
		"IdpName": true,
	}

	typ := reflect.TypeOf(models.Organization{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		switch field.Type.Kind() {
		case reflect.Ptr, reflect.Slice, reflect.Map, reflect.Chan, reflect.Interface:
			if !cloned[field.Name] {
				t.Errorf("models.Organization.%s is a %s, so a struct copy still aliases it, "+
					"but cloneOrganization does not copy it. Teach cloneOrganization about "+
					"this field and add it to this test's list.", field.Name, field.Type.Kind())
			}
		case reflect.Struct:
			// time.Time is the only struct field today. It is a value type by
			// contract (its internal *Location points at a process-global that
			// is never mutated), so a struct copy is sufficient. Any OTHER
			// struct field needs its own judgement.
			if field.Type != reflect.TypeOf(time.Time{}) {
				t.Errorf("models.Organization.%s is a %s struct: decide whether it needs a "+
					"deeper copy in cloneOrganization, then record the decision here.",
					field.Name, field.Type)
			}
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
