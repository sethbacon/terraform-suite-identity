package store

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

var apiKeyCols = []string{
	"id", "user_id", "organization_id", "name", "description",
	"key_hash", "key_prefix", "scopes", "expires_at", "last_used_at", "expiry_notification_sent_at", "created_at",
}

var apiKeyListCols = []string{
	"id", "user_id", "organization_id", "name", "description",
	"key_hash", "key_prefix", "scopes", "expires_at", "last_used_at", "expiry_notification_sent_at", "created_at", "user_name",
}

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

var sampleScopes = []byte(`["modules:read","modules:write"]`)

func sampleAPIKeyRow() *sqlmock.Rows {
	return sqlmock.NewRows(apiKeyCols).
		AddRow("key-1", "user-1", "org-1", "CI Key", nil, "hashedkey", "tfr_abc123",
			sampleScopes, nil, nil, nil, time.Now())
}

func emptyAPIKeyRow() *sqlmock.Rows {
	return sqlmock.NewRows(apiKeyCols)
}

func sampleAPIKeyListRow() *sqlmock.Rows {
	return sqlmock.NewRows(apiKeyListCols).
		AddRow("key-1", "user-1", "org-1", "CI Key", nil, "hashedkey", "tfr_abc123",
			sampleScopes, nil, nil, nil, time.Now(), nil)
}

func newAPIKeyRepo(t *testing.T) (*APIKeyRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewAPIKeyRepository(db), mock
}

// ---------------------------------------------------------------------------
// CreateAPIKey
// ---------------------------------------------------------------------------

func TestCreateAPIKey_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("INSERT INTO api_keys").
		WillReturnResult(sqlmock.NewResult(1, 1))

	key := &models.APIKey{
		ID:             "key-new",
		OrganizationID: "org-1",
		Name:           "Test Key",
		KeyHash:        "hash",
		KeyPrefix:      "tfr_test",
		Scopes:         []string{"modules:read"},
	}
	if err := repo.CreateAPIKey(context.Background(), key, OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateAPIKey_DBError(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("INSERT INTO api_keys").
		WillReturnError(errDB)

	key := &models.APIKey{ID: "key-new", Scopes: []string{"modules:read"}}
	if err := repo.CreateAPIKey(context.Background(), key, OrgScopeAllOrganizations()); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetAPIKeyByID
// ---------------------------------------------------------------------------

func TestGetAPIKeyByID_Found(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE id").
		WithArgs("key-1").
		WillReturnRows(sampleAPIKeyRow())

	key, err := repo.GetAPIKeyByID(context.Background(), "key-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key == nil {
		t.Fatal("expected key, got nil")
	}
}

func TestGetAPIKeyByID_NotFound(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE id").
		WillReturnRows(emptyAPIKeyRow())

	key, err := repo.GetAPIKeyByID(context.Background(), "missing", OrgScopeAllOrganizations())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if key != nil {
		t.Error("expected nil, got non-nil")
	}
}

// ---------------------------------------------------------------------------
// ListAPIKeysByUser
// ---------------------------------------------------------------------------

func TestListAPIKeysByUser_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*user_id").
		WillReturnRows(sampleAPIKeyListRow())

	keys, err := repo.ListAPIKeysByUser(context.Background(), "user-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("len(keys) = %d, want 1", len(keys))
	}
}

func TestListAPIKeysByUser_Empty(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*user_id").
		WillReturnRows(sqlmock.NewRows(apiKeyListCols))

	keys, err := repo.ListAPIKeysByUser(context.Background(), "user-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("len(keys) = %d, want 0", len(keys))
	}
}

// ---------------------------------------------------------------------------
// ListAPIKeysByOrganization
// ---------------------------------------------------------------------------

func TestListAPIKeysByOrganization_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*organization_id").
		WillReturnRows(sampleAPIKeyListRow())

	keys, err := repo.ListAPIKeysByOrganization(context.Background(), "org-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("len(keys) = %d, want 1", len(keys))
	}
}

// ---------------------------------------------------------------------------
// UpdateLastUsed
// ---------------------------------------------------------------------------

func TestUpdateLastUsed_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("UPDATE api_keys.*SET last_used_at").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UpdateLastUsed(context.Background(), "key-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RevokeAPIKey
// ---------------------------------------------------------------------------

func TestRevokeAPIKey_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("DELETE FROM api_keys").
		WithArgs("key-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.RevokeAPIKey(context.Background(), "key-1", OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DeleteExpiredKeys
// ---------------------------------------------------------------------------

func TestDeleteExpiredKeys_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("DELETE FROM api_keys.*WHERE.*expires_at").
		WillReturnResult(sqlmock.NewResult(0, 4))

	n, err := repo.DeleteExpiredKeys(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 4 {
		t.Fatalf("deleted %d keys, want 4", n)
	}
}

// TestDeleteExpiredKeys_NoRowsIsNotAnError pins the bulk half of the not-found
// contract: a sweep that finds nothing reports 0, not ErrNotFound.
func TestDeleteExpiredKeys_NoRowsIsNotAnError(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("DELETE FROM api_keys.*WHERE.*expires_at").
		WillReturnResult(sqlmock.NewResult(0, 0))

	n, err := repo.DeleteExpiredKeys(context.Background())
	if err != nil {
		t.Fatalf("a bulk sweep that matched nothing must not be an error: %v", err)
	}
	if n != 0 {
		t.Fatalf("deleted %d keys, want 0", n)
	}
}

// ---------------------------------------------------------------------------
// GetAPIKeysByPrefix
// ---------------------------------------------------------------------------

func TestGetAPIKeysByPrefix_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix.*expires_at").
		WillReturnRows(sampleAPIKeyRow())

	keys, err := repo.GetAPIKeysByPrefix(context.Background(), "tfr_abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("len(keys) = %d, want 1", len(keys))
	}
}

// TestGetAPIKeysByPrefix_ExcludesExpired proves the query-level expiry filter
// (WHERE key_prefix = $1 AND (expires_at IS NULL OR expires_at > NOW())):
// an expired row is excluded from the returned candidates while a
// non-expired row and a NULL-expiry row are both included. sqlmock returns
// exactly the rows the mock is told to return, so this test exercises the
// scan/assembly path with a row set that models what the real WHERE clause
// would filter down to, proving the repository doesn't do any additional
// (incorrect) filtering of its own that would also exclude the good rows.
func TestGetAPIKeysByPrefix_ExcludesExpired(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)

	future := time.Now().Add(24 * time.Hour)
	rows := sqlmock.NewRows(apiKeyCols).
		AddRow("key-active", "user-1", "org-1", "Active Key", nil, "hash-active", "tfr_abc123",
			sampleScopes, future, nil, nil, time.Now()).
		AddRow("key-nullexp", "user-1", "org-1", "No-Expiry Key", nil, "hash-nullexp", "tfr_abc123",
			sampleScopes, nil, nil, nil, time.Now())
		// An expired row is deliberately NOT added here: the SQL WHERE clause
		// (expires_at IS NULL OR expires_at > NOW()) excludes it at the
		// database level, so the repository must never see it in the result set.

	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix.*expires_at.*IS NULL.*expires_at.*NOW").
		WithArgs("tfr_abc123", maxPrefixCandidates+1).
		WillReturnRows(rows)

	keys, err := repo.GetAPIKeysByPrefix(context.Background(), "tfr_abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("len(keys) = %d, want 2 (active + null-expiry, expired excluded by the query)", len(keys))
	}
	ids := map[string]bool{keys[0].ID: true, keys[1].ID: true}
	if !ids["key-active"] || !ids["key-nullexp"] {
		t.Errorf("expected key-active and key-nullexp in results, got %v", ids)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetAPIKeysByPrefix — bounded fan-out (issue #136)
// ---------------------------------------------------------------------------

// prefixRows builds n candidate rows all sharing one key_prefix: the shape a
// degenerate prefix produces, where the discriminator has stopped
// discriminating and the lookup returns the population rather than a candidate
// set.
func prefixRows(n int) *sqlmock.Rows {
	rows := sqlmock.NewRows(apiKeyCols)
	for i := 0; i < n; i++ {
		rows.AddRow(
			"key-"+strconv.Itoa(i), "user-1", "org-1", "Key "+strconv.Itoa(i), nil,
			"hash-"+strconv.Itoa(i), "tfregistry", sampleScopes, nil, nil, nil, time.Now())
	}
	return rows
}

// TestGetAPIKeysByPrefix_QueryIsBounded proves the LIMIT reaches the database
// rather than being applied after the fact.
//
// Trimming an unbounded result set in Go would leave the DATABASE doing the
// full scan and shipping every row across the wire, which is most of the cost
// the bound exists to avoid. sqlmock's argument matching is what distinguishes
// the two: the limit has to be a query parameter for this to pass.
//
// The bound is fetched as maxPrefixCandidates+1 so saturation is DETECTABLE —
// a query limited to exactly the budget cannot tell a table holding the budget
// apart from one holding ten thousand.
func TestGetAPIKeysByPrefix_QueryIsBounded(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix.*LIMIT").
		WithArgs("tfr_abc", maxPrefixCandidates+1).
		WillReturnRows(sampleAPIKeyRow())

	if _, err := repo.GetAPIKeysByPrefix(context.Background(), "tfr_abc"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the lookup did not push its bound into the query: %v", err)
	}
}

// TestGetAPIKeysByPrefix_FanOutBoundary is the bidirectional table for the
// saturation refusal.
//
// A table asserting only the refusal would pass against a repository that
// refused every lookup — which denies all authentication and is a worse
// outage than the DoS it was meant to prevent. So the row at exactly the
// budget must SUCCEED and return every candidate, and only the row past it may
// fail.
func TestGetAPIKeysByPrefix_FanOutBoundary(t *testing.T) {
	tests := []struct {
		name    string
		rows    int
		wantErr bool
		why     string
	}{
		{
			name: "well under the budget: the ordinary case",
			rows: 3,
			why:  "a discriminating prefix selects a handful of candidates and must be served",
		},
		{
			name: "exactly at the budget: still a usable candidate set",
			rows: maxPrefixCandidates,
			why: "the budget is an inclusive ceiling; refusing here would deny a deployment " +
				"that is large but still bounded",
		},
		{
			name:    "one past the budget: the prefix is not discriminating",
			rows:    maxPrefixCandidates + 1,
			wantErr: true,
			why: "past this point the prefix has stopped narrowing anything, and serving the set " +
				"would hand the caller an unbounded bcrypt loop for an unauthenticated request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, mock := newAPIKeyRepo(t)
			mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix.*LIMIT").
				WithArgs("tfregistry", maxPrefixCandidates+1).
				WillReturnRows(prefixRows(tt.rows))

			keys, err := repo.GetAPIKeysByPrefix(context.Background(), "tfregistry")

			if !tt.wantErr {
				if err != nil {
					t.Fatalf("GetAPIKeysByPrefix with %d candidates = %v, want success (%s)", tt.rows, err, tt.why)
				}
				if len(keys) != tt.rows {
					t.Fatalf("returned %d candidates, want all %d — a silently truncated set makes "+
						"authentication depend on created_at ordering", len(keys), tt.rows)
				}
				return
			}

			if err == nil {
				t.Fatalf("GetAPIKeysByPrefix served %d candidates without complaint (%s)", tt.rows, tt.why)
			}
			if !errors.Is(err, ErrPrefixNotDiscriminating) {
				t.Fatalf("error = %v, want it to wrap ErrPrefixNotDiscriminating so a host can tell "+
					"an actionable configuration fault from a transient database error", err)
			}
			// Returning the partial set alongside the error would let a caller
			// that checks only `len(keys)` walk straight into the bcrypt loop
			// this refusal exists to prevent.
			if keys != nil {
				t.Fatalf("returned %d candidates alongside the refusal, want nil", len(keys))
			}
		})
	}
}

// TestGetAPIKeysByPrefix_SaturationErrorIsActionable pins that the refusal
// names what an operator has to DO about it.
//
// The condition is not transient and cannot be retried away: the affected keys
// were minted under the old cap and have to be re-issued. An error that only
// said "too many results" would be read as load and route to the wrong fix.
func TestGetAPIKeysByPrefix_SaturationErrorIsActionable(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*key_prefix.*LIMIT").
		WillReturnRows(prefixRows(maxPrefixCandidates + 1))

	_, err := repo.GetAPIKeysByPrefix(context.Background(), "tfregistry")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	for _, want := range []string{"tfregistry", "re-issued", "MaxAPIKeyPrefixLength"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err.Error(), want)
		}
	}
}

// ---------------------------------------------------------------------------
// ListAll
// ---------------------------------------------------------------------------

func TestListAllAPIKeys_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys").
		WillReturnRows(sampleAPIKeyListRow())

	keys, err := repo.ListAPIKeys(context.Background(), OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("len(keys) = %d, want 1", len(keys))
	}
}

// ---------------------------------------------------------------------------
// ListByUserAndOrganization
// ---------------------------------------------------------------------------

func TestListByUserAndOrganization_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*user_id.*organization_id").
		WillReturnRows(sampleAPIKeyListRow())

	keys, err := repo.ListByUserAndOrganization(context.Background(), "user-1", "org-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("len(keys) = %d, want 1", len(keys))
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestAPIKey_Update_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("UPDATE api_keys").
		WillReturnResult(sqlmock.NewResult(1, 1))

	key := &models.APIKey{ID: "key-1", Name: "updated", Scopes: []string{"read"}}
	if err := repo.Update(context.Background(), key, OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIKey_Update_DBError(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("UPDATE api_keys").
		WillReturnError(errDB)

	key := &models.APIKey{ID: "key-1", Name: "updated", Scopes: []string{"read"}}
	if err := repo.Update(context.Background(), key, OrgScopeAllOrganizations()); err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// FindExpiringKeys
// ---------------------------------------------------------------------------

var expiringKeyCols = []string{
	"id", "user_id", "organization_id", "name", "description",
	"key_hash", "key_prefix", "scopes", "expires_at", "last_used_at",
	"expiry_notification_sent_at", "created_at",
}

func TestFindExpiringKeys_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)

	rows := sqlmock.NewRows(expiringKeyCols).
		AddRow("key-1", "user-1", "org-1", "CI Key", nil, "hashedkey", "tfr_abc123",
			sampleScopes, nil, nil, nil, time.Now())
	mock.ExpectQuery("SELECT.*FROM api_keys").
		WillReturnRows(rows)

	keys, err := repo.FindExpiringKeys(context.Background(), 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("len = %d, want 1", len(keys))
	}
}

func TestFindExpiringKeys_Empty(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)

	mock.ExpectQuery("SELECT.*FROM api_keys").
		WillReturnRows(mock.NewRows(expiringKeyCols))

	keys, err := repo.FindExpiringKeys(context.Background(), 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected empty slice, got %d", len(keys))
	}
}

func TestFindExpiringKeys_DBError(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)

	mock.ExpectQuery("SELECT.*FROM api_keys").
		WillReturnError(errDB)

	_, err := repo.FindExpiringKeys(context.Background(), 7)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ClaimExpiryNotification
// ---------------------------------------------------------------------------

func TestClaimExpiryNotification_Won(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)

	// The conditional UPDATE affected the row -> this caller won the claim.
	mock.ExpectExec("UPDATE api_keys SET expiry_notification_sent_at").
		WillReturnResult(sqlmock.NewResult(0, 1))

	claimed, err := repo.ClaimExpiryNotification(context.Background(), "key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !claimed {
		t.Error("claimed = false, want true when one row was updated")
	}
}

func TestClaimExpiryNotification_AlreadyClaimed(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)

	// 0 rows affected: another replica already set expiry_notification_sent_at.
	mock.ExpectExec("UPDATE api_keys SET expiry_notification_sent_at").
		WillReturnResult(sqlmock.NewResult(0, 0))

	claimed, err := repo.ClaimExpiryNotification(context.Background(), "key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claimed {
		t.Error("claimed = true, want false when no row was updated")
	}
}

func TestClaimExpiryNotification_DBError(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)

	mock.ExpectExec("UPDATE api_keys SET expiry_notification_sent_at").
		WillReturnError(errDB)

	if _, err := repo.ClaimExpiryNotification(context.Background(), "key-1"); err == nil {
		t.Error("expected error, got nil")
	}
}
