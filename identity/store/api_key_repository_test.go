package store

import (
	"context"
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
	db, mock, err := sqlmock.New()
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
	if err := repo.CreateAPIKey(context.Background(), key); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateAPIKey_DBError(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("INSERT INTO api_keys").
		WillReturnError(errDB)

	key := &models.APIKey{ID: "key-new", Scopes: []string{"modules:read"}}
	if err := repo.CreateAPIKey(context.Background(), key); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetAPIKeyByHash
// ---------------------------------------------------------------------------

func TestGetAPIKeyByHash_Found(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE key_hash").
		WithArgs("hashedkey").
		WillReturnRows(sampleAPIKeyRow())

	key, err := repo.GetAPIKeyByHash(context.Background(), "hashedkey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key == nil {
		t.Fatal("expected key, got nil")
	}
	if key.ID != "key-1" {
		t.Errorf("ID = %s, want key-1", key.ID)
	}
	if len(key.Scopes) != 2 {
		t.Errorf("len(Scopes) = %d, want 2", len(key.Scopes))
	}
}

func TestGetAPIKeyByHash_NotFound(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE key_hash").
		WillReturnRows(emptyAPIKeyRow())

	key, err := repo.GetAPIKeyByHash(context.Background(), "missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("expected nil, got non-nil")
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

	key, err := repo.GetAPIKeyByID(context.Background(), "key-1")
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

	key, err := repo.GetAPIKeyByID(context.Background(), "missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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

	keys, err := repo.ListAPIKeysByUser(context.Background(), "user-1")
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

	keys, err := repo.ListAPIKeysByUser(context.Background(), "user-1")
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

	keys, err := repo.ListAPIKeysByOrganization(context.Background(), "org-1")
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

	if err := repo.RevokeAPIKey(context.Background(), "key-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DeleteExpiredKeys
// ---------------------------------------------------------------------------

func TestDeleteExpiredKeys_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("DELETE FROM api_keys.*WHERE.*expires_at").
		WillReturnResult(sqlmock.NewResult(0, 0))

	if err := repo.DeleteExpiredKeys(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
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
		WithArgs("tfr_abc123").
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
// ListAll
// ---------------------------------------------------------------------------

func TestListAllAPIKeys_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys").
		WillReturnRows(sampleAPIKeyListRow())

	keys, err := repo.ListAll(context.Background())
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

	keys, err := repo.ListByUserAndOrganization(context.Background(), "user-1", "org-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("len(keys) = %d, want 1", len(keys))
	}
}

// ---------------------------------------------------------------------------
// Delegate aliases (Create / GetByID / Update / Delete / ListByUser / ListByOrganization)
// ---------------------------------------------------------------------------

func TestAPIKey_Create_Delegate(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("INSERT INTO api_keys").
		WillReturnResult(sqlmock.NewResult(1, 1))

	key := &models.APIKey{ID: "k1", OrganizationID: "org-1", Name: "k", KeyHash: "h", KeyPrefix: "p", Scopes: []string{"read"}}
	if err := repo.Create(context.Background(), key); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIKey_GetByID_Delegate(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*id").
		WillReturnRows(sampleAPIKeyRow())

	k, err := repo.GetByID(context.Background(), "key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k == nil {
		t.Fatal("expected key, got nil")
	}
}

func TestAPIKey_Update_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("UPDATE api_keys").
		WillReturnResult(sqlmock.NewResult(1, 1))

	key := &models.APIKey{ID: "key-1", Name: "updated", Scopes: []string{"read"}}
	if err := repo.Update(context.Background(), key); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIKey_Update_DBError(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("UPDATE api_keys").
		WillReturnError(errDB)

	key := &models.APIKey{ID: "key-1", Name: "updated", Scopes: []string{"read"}}
	if err := repo.Update(context.Background(), key); err == nil {
		t.Error("expected error")
	}
}

func TestAPIKey_Delete_Delegate(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Delete(context.Background(), "key-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIKey_ListByUser_Delegate(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*user_id").
		WillReturnRows(sampleAPIKeyListRow())

	keys, err := repo.ListByUser(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("len = %d, want 1", len(keys))
	}
}

func TestAPIKey_ListByOrganization_Delegate(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)
	mock.ExpectQuery("SELECT.*FROM api_keys.*WHERE.*organization_id").
		WillReturnRows(sampleAPIKeyListRow())

	keys, err := repo.ListByOrganization(context.Background(), "org-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("len = %d, want 1", len(keys))
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
// MarkExpiryNotificationSent
// ---------------------------------------------------------------------------

func TestMarkExpiryNotificationSent_Success(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)

	mock.ExpectExec("UPDATE api_keys SET expiry_notification_sent_at").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.MarkExpiryNotificationSent(context.Background(), "key-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMarkExpiryNotificationSent_DBError(t *testing.T) {
	repo, mock := newAPIKeyRepo(t)

	mock.ExpectExec("UPDATE api_keys SET expiry_notification_sent_at").
		WillReturnError(errDB)

	if err := repo.MarkExpiryNotificationSent(context.Background(), "key-1"); err == nil {
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
