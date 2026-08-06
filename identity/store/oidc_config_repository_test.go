package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

var errOIDCDB = errors.New("oidc db error")

func newOIDCConfigRepo(t *testing.T) (*OIDCConfigRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewOIDCConfigRepository(sqlx.NewDb(db, "sqlmock")), mock
}

var oidcConfigCols = []string{
	"id", "name", "provider_type", "issuer_url", "client_id",
	"client_secret_encrypted", "redirect_url", "scopes", "is_active",
	"extra_config", "created_at", "updated_at", "created_by", "updated_by",
}

// TestCreateOIDCConfig_Success covers the IsActive=false path, which remains
// a plain, untransacted insert (no change in behavior for this case).
func TestCreateOIDCConfig_Success(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectExec("INSERT INTO oidc_config").
		WillReturnResult(sqlmock.NewResult(0, 1))

	cfg := &models.OIDCConfig{
		ID:           uuid.New(),
		Name:         "test",
		ProviderType: "generic_oidc",
		IssuerURL:    "https://issuer.example.com",
		ClientID:     "client-id",
		RedirectURL:  "https://app.example.com/callback",
		IsActive:     false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := repo.CreateOIDCConfig(context.Background(), cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestCreateOIDCConfig_Error covers the IsActive=false plain-insert error path.
func TestCreateOIDCConfig_Error(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectExec("INSERT INTO oidc_config").
		WillReturnError(errOIDCDB)

	if err := repo.CreateOIDCConfig(context.Background(), &models.OIDCConfig{ID: uuid.New()}); err == nil {
		t.Error("expected error")
	}
}

// TestCreateOIDCConfig_ActiveSuccess covers the IsActive=true path: it must
// enforce the single-active-config invariant by deactivating all existing
// configs and inserting the new one as active, all within one transaction
// (mirroring ActivateOIDCConfig's transactional pattern below).
func TestCreateOIDCConfig_ActiveSuccess(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE oidc_config SET is_active = false").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO oidc_config").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	cfg := &models.OIDCConfig{
		ID:           uuid.New(),
		Name:         "test",
		ProviderType: "generic_oidc",
		IssuerURL:    "https://issuer.example.com",
		ClientID:     "client-id",
		RedirectURL:  "https://app.example.com/callback",
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := repo.CreateOIDCConfig(context.Background(), cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateOIDCConfig_ActiveBeginError(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectBegin().WillReturnError(errOIDCDB)

	if err := repo.CreateOIDCConfig(context.Background(), &models.OIDCConfig{ID: uuid.New(), IsActive: true}); err == nil {
		t.Error("expected error from Begin")
	}
}

func TestCreateOIDCConfig_ActiveDeactivateError(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE oidc_config SET is_active = false").
		WillReturnError(errOIDCDB)
	mock.ExpectRollback()

	if err := repo.CreateOIDCConfig(context.Background(), &models.OIDCConfig{ID: uuid.New(), IsActive: true}); err == nil {
		t.Error("expected error from deactivation")
	}
}

func TestCreateOIDCConfig_ActiveInsertError(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE oidc_config SET is_active = false").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO oidc_config").
		WillReturnError(errOIDCDB)
	mock.ExpectRollback()

	if err := repo.CreateOIDCConfig(context.Background(), &models.OIDCConfig{ID: uuid.New(), IsActive: true}); err == nil {
		t.Error("expected error from insert")
	}
}

// TestGetActiveOIDCConfig_Found also asserts the query orders by
// updated_at DESC — a defensive, deterministic tie-break so that if two rows
// are ever somehow both is_active=true, the most-recently-updated one wins
// consistently rather than an implementation-defined row being returned.
func TestGetActiveOIDCConfig_Found(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	id := uuid.New()
	now := time.Now()
	mock.ExpectQuery("SELECT.*FROM oidc_config WHERE is_active.*ORDER BY updated_at DESC").
		WillReturnRows(sqlmock.NewRows(oidcConfigCols).AddRow(
			id, "default", "generic_oidc", "https://issuer.example.com", "client-id",
			"encrypted-secret", "https://app/callback", []byte(`["openid"]`), true,
			[]byte(`{}`), now, now, nil, nil,
		))

	cfg, err := repo.GetActiveOIDCConfig(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil || cfg.ID != id {
		t.Fatalf("cfg = %v, want id %v", cfg, id)
	}
}

func TestGetActiveOIDCConfig_NotFound(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM oidc_config WHERE is_active").
		WillReturnError(sql.ErrNoRows)

	cfg, err := repo.GetActiveOIDCConfig(context.Background())
	if !errors.Is(err, ErrNotFound) || cfg != nil {
		t.Fatalf("got (%v, %v), want (nil, ErrNotFound)", cfg, err)
	}
}

func TestGetActiveOIDCConfig_Error(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM oidc_config WHERE is_active").
		WillReturnError(errOIDCDB)

	if _, err := repo.GetActiveOIDCConfig(context.Background()); err == nil {
		t.Error("expected error")
	}
}

func TestGetOIDCConfig_Found(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	id := uuid.New()
	now := time.Now()
	mock.ExpectQuery("SELECT.*FROM oidc_config WHERE id").
		WillReturnRows(sqlmock.NewRows(oidcConfigCols).AddRow(
			id, "test", "generic_oidc", "https://issuer.example.com", "client",
			"enc", "https://app/callback", []byte(`["openid"]`), true,
			[]byte(`{}`), now, now, nil, nil,
		))

	cfg, err := repo.GetOIDCConfig(context.Background(), id)
	if err != nil || cfg == nil {
		t.Fatalf("got (%v, %v), want a config", cfg, err)
	}
}

func TestGetOIDCConfig_NotFound(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM oidc_config WHERE id").
		WillReturnError(sql.ErrNoRows)

	cfg, err := repo.GetOIDCConfig(context.Background(), uuid.New())
	if !errors.Is(err, ErrNotFound) || cfg != nil {
		t.Fatalf("got (%v, %v), want (nil, ErrNotFound)", cfg, err)
	}
}

func TestListOIDCConfigs_Success(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	id := uuid.New()
	now := time.Now()
	mock.ExpectQuery("SELECT.*FROM oidc_config ORDER BY").
		WillReturnRows(sqlmock.NewRows(oidcConfigCols).AddRow(
			id, "default", "generic_oidc", "https://a.com", "c",
			"e", "https://r.com", []byte(`["openid"]`), true,
			[]byte(`{}`), now, now, nil, nil,
		))

	configs, err := repo.ListOIDCConfigs(context.Background())
	if err != nil || len(configs) != 1 {
		t.Fatalf("got (%d, %v), want (1, nil)", len(configs), err)
	}
}

func TestListOIDCConfigs_Empty(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectQuery("SELECT.*FROM oidc_config ORDER BY").
		WillReturnRows(sqlmock.NewRows(oidcConfigCols))

	configs, err := repo.ListOIDCConfigs(context.Background())
	if err != nil || len(configs) != 0 {
		t.Fatalf("got (%d, %v), want (0, nil)", len(configs), err)
	}
}

func TestDeleteOIDCConfig_Success(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectExec("DELETE FROM oidc_config WHERE id").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repo.DeleteOIDCConfig(context.Background(), uuid.New()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteOIDCConfig_Error(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectExec("DELETE FROM oidc_config WHERE id").
		WillReturnError(errOIDCDB)

	if err := repo.DeleteOIDCConfig(context.Background(), uuid.New()); err == nil {
		t.Error("expected error")
	}
}

func TestDeactivateAllOIDCConfigs_Success(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectExec("UPDATE oidc_config SET is_active = false").
		WillReturnResult(sqlmock.NewResult(0, 2))

	n, err := repo.DeactivateAllOIDCConfigs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 2 {
		t.Fatalf("deactivated %d configs, want 2", n)
	}
}

func TestActivateOIDCConfig_Success(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE oidc_config SET is_active = false").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE oidc_config SET is_active = true").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := repo.ActivateOIDCConfig(context.Background(), uuid.New()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestActivateOIDCConfig_BeginError(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectBegin().WillReturnError(errOIDCDB)

	if err := repo.ActivateOIDCConfig(context.Background(), uuid.New()); err == nil {
		t.Error("expected error from Begin")
	}
}

func TestActivateOIDCConfig_DeactivateError(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE oidc_config SET is_active = false").
		WillReturnError(errOIDCDB)
	mock.ExpectRollback()

	if err := repo.ActivateOIDCConfig(context.Background(), uuid.New()); err == nil {
		t.Error("expected error from deactivation")
	}
}

func TestActivateOIDCConfig_ActivateError(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE oidc_config SET is_active = false").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE oidc_config SET is_active = true").
		WillReturnError(errOIDCDB)
	mock.ExpectRollback()

	if err := repo.ActivateOIDCConfig(context.Background(), uuid.New()); err == nil {
		t.Error("expected error from activation")
	}
}

func TestUpdateOIDCConfigExtraConfig_Success(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectExec("UPDATE oidc_config SET extra_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UpdateOIDCConfigExtraConfig(context.Background(), uuid.New(), []byte(`{"group_claim":"groups"}`)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateOIDCConfigExtraConfig_DBError(t *testing.T) {
	repo, mock := newOIDCConfigRepo(t)
	mock.ExpectExec("UPDATE oidc_config SET extra_config").
		WillReturnError(errOIDCDB)

	if err := repo.UpdateOIDCConfigExtraConfig(context.Background(), uuid.New(), []byte(`{}`)); err == nil {
		t.Error("expected error, got nil")
	}
}
