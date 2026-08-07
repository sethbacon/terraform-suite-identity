package notify

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/sethbacon/terraform-suite-identity/identity/mailer"
	identitystore "github.com/sethbacon/terraform-suite-identity/identity/store"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var testExpiryOpts = ExpiryOptions{ProductName: "Test Suite App"}

func newExpiryConfig(enabled bool, smtpHost string) ExpiryConfig {
	return ExpiryConfig{
		Enabled: enabled,
		SMTP: mailer.Config{
			Host: smtpHost,
			Port: 25,
			From: "noreply@example.com",
		},
		APIKeyExpiring:     true,
		WarningDays:        7,
		CheckIntervalHours: 24,
	}
}

func newExpiryConfigProvider(cfg ExpiryConfig) ExpiryConfigProvider {
	return func() ExpiryConfig { return cfg }
}

func newAPIKeyRepoForNotifier(t *testing.T) (*identitystore.APIKeyRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (apikey): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return identitystore.NewAPIKeyRepository(db), mock
}

func newUserRepoForNotifier(t *testing.T) (*identitystore.UserRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (user): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return identitystore.NewUserRepository(db), mock
}

// ---------------------------------------------------------------------------
// NewAPIKeyExpiryNotifier — construction and interval defaulting
// ---------------------------------------------------------------------------

func TestNewAPIKeyExpiryNotifier_DefaultInterval(t *testing.T) {
	cfg := newExpiryConfig(true, "smtp.example.com")
	cfg.CheckIntervalHours = 0 // should default to 24

	n := NewAPIKeyExpiryNotifier(nil, nil, newExpiryConfigProvider(cfg), testExpiryOpts)
	if n == nil {
		t.Fatal("NewAPIKeyExpiryNotifier returned nil")
	}
	if n.interval != 24*time.Hour {
		t.Errorf("interval = %v, want 24h", n.interval)
	}
}

func TestNewAPIKeyExpiryNotifier_NegativeInterval_Defaults24h(t *testing.T) {
	cfg := newExpiryConfig(true, "smtp.example.com")
	cfg.CheckIntervalHours = -5

	n := NewAPIKeyExpiryNotifier(nil, nil, newExpiryConfigProvider(cfg), testExpiryOpts)
	if n.interval != 24*time.Hour {
		t.Errorf("interval = %v, want 24h", n.interval)
	}
}

func TestNewAPIKeyExpiryNotifier_CustomInterval(t *testing.T) {
	cfg := newExpiryConfig(true, "smtp.example.com")
	cfg.CheckIntervalHours = 48

	n := NewAPIKeyExpiryNotifier(nil, nil, newExpiryConfigProvider(cfg), testExpiryOpts)
	if n.interval != 48*time.Hour {
		t.Errorf("interval = %v, want 48h", n.interval)
	}
}

func TestNewAPIKeyExpiryNotifier_StopChanInitialised(t *testing.T) {
	n := NewAPIKeyExpiryNotifier(nil, nil, newExpiryConfigProvider(newExpiryConfig(true, "smtp.example.com")), testExpiryOpts)
	if n.stopChan == nil {
		t.Error("stopChan should not be nil after construction")
	}
}

// ---------------------------------------------------------------------------
// Start — early exits (no goroutine needed)
// ---------------------------------------------------------------------------

func TestExpiryNotifier_Start_DisabledConfig(t *testing.T) {
	cfg := newExpiryConfig(false, "smtp.example.com")
	n := NewAPIKeyExpiryNotifier(nil, nil, newExpiryConfigProvider(cfg), testExpiryOpts)

	done := make(chan struct{})
	go func() {
		_ = n.Start(context.Background())
		close(done)
	}()

	select {
	case <-done:
		// Start returned immediately because Enabled=false
	case <-time.After(2 * time.Second):
		t.Error("Start did not return quickly when notifications are disabled")
	}
}

func TestExpiryNotifier_Start_BlankSMTPHost(t *testing.T) {
	cfg := newExpiryConfig(true, "") // blank host → should exit
	n := NewAPIKeyExpiryNotifier(nil, nil, newExpiryConfigProvider(cfg), testExpiryOpts)

	done := make(chan struct{})
	go func() {
		_ = n.Start(context.Background())
		close(done)
	}()

	select {
	case <-done:
		// Start returned immediately because SMTP host is blank
	case <-time.After(2 * time.Second):
		t.Error("Start did not return quickly when SMTP host is blank")
	}
}

// ---------------------------------------------------------------------------
// Stop — channel close
// ---------------------------------------------------------------------------

func TestExpiryNotifier_Stop_DoesNotPanic(t *testing.T) {
	n := NewAPIKeyExpiryNotifier(nil, nil, newExpiryConfigProvider(newExpiryConfig(true, "smtp.example.com")), testExpiryOpts)
	_ = n.Stop() // must not panic
}

// ---------------------------------------------------------------------------
// sendExpiryEmail — covers body composition up to the mailer.Send call.
// Uses an unreachable SMTP address so the formatting code is executed and
// the send step fails with "connection refused" (which is expected).
// ---------------------------------------------------------------------------

func TestExpiryNotifier_SendExpiryEmail_NoTLS_CoverBodyComposition(t *testing.T) {
	cfg := newExpiryConfig(true, "127.0.0.1")
	cfg.SMTP.Port = 1 // nothing listening on port 1
	cfg.SMTP.TLSMode = mailer.TLSDisabled

	n := NewAPIKeyExpiryNotifier(nil, nil, newExpiryConfigProvider(cfg), testExpiryOpts)
	expiresAt := time.Now().Add(5 * 24 * time.Hour)

	// Error is expected (connection refused); we only care that no panic occurs
	// and that all the body-composition statements are exercised.
	_ = n.sendExpiryEmail(context.Background(), cfg.SMTP, "user@example.com", "Alice", "CI Key", "tfr_abc", expiresAt)
}

func TestExpiryNotifier_SendExpiryEmail_TLS_CoverSendTLS(t *testing.T) {
	cfg := newExpiryConfig(true, "127.0.0.1")
	cfg.SMTP.Port = 1                     // nothing listening on port 1
	cfg.SMTP.TLSMode = mailer.TLSRequired // routes through sendTLS, which falls back to sendStartTLS on dial failure

	n := NewAPIKeyExpiryNotifier(nil, nil, newExpiryConfigProvider(cfg), testExpiryOpts)
	expiresAt := time.Now().Add(3 * 24 * time.Hour)

	_ = n.sendExpiryEmail(context.Background(), cfg.SMTP, "user@example.com", "Bob", "Deploy Key", "tfr_xyz", expiresAt)
}

func TestExpiryNotifier_SendExpiryEmail_AlreadyExpired(t *testing.T) {
	cfg := newExpiryConfig(true, "127.0.0.1")
	cfg.SMTP.Port = 1
	cfg.SMTP.TLSMode = mailer.TLSDisabled

	n := NewAPIKeyExpiryNotifier(nil, nil, newExpiryConfigProvider(cfg), testExpiryOpts)
	// expiresAt in the past → daysLeft clamps to 0
	expiresAt := time.Now().Add(-48 * time.Hour)

	_ = n.sendExpiryEmail(context.Background(), cfg.SMTP, "user@example.com", "Carol", "Old Key", "tfr_old", expiresAt)
}

// ---------------------------------------------------------------------------
// runCheck — exercised via sqlmock
// ---------------------------------------------------------------------------

// findExpiringKeysCols mirrors the SELECT columns in identity/store's
// FindExpiringKeys, which shares scanAPIKey's full 12-column projection
// (expiry_notification_sent_at included). It must match exactly: a short
// column list makes every row fail to scan, so a test that thinks it is
// exercising the per-key loop would silently only exercise the query error
// path.
var findExpiringKeysCols = []string{
	"id", "user_id", "organization_id", "name", "description",
	"key_hash", "key_prefix", "scopes", "expires_at", "last_used_at",
	"expiry_notification_sent_at", "created_at",
}

var userColsForNotifier = []string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}

func TestExpiryNotifier_RunCheck_DefaultWarningDays(t *testing.T) {
	// WarningDays = 0 → defaults to 7 inside runCheck
	apiKeyRepo, apiKeyMock := newAPIKeyRepoForNotifier(t)
	cfg := newExpiryConfig(true, "smtp.example.com")
	cfg.WarningDays = 0

	n := NewAPIKeyExpiryNotifier(apiKeyRepo, nil, newExpiryConfigProvider(cfg), testExpiryOpts)

	apiKeyMock.ExpectQuery("SELECT.*FROM api_keys").
		WillReturnRows(sqlmock.NewRows(findExpiringKeysCols))

	n.runCheck(context.Background())

	if err := apiKeyMock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestExpiryNotifier_RunCheck_DBError(t *testing.T) {
	apiKeyRepo, apiKeyMock := newAPIKeyRepoForNotifier(t)
	cfg := newExpiryConfig(true, "smtp.example.com")

	n := NewAPIKeyExpiryNotifier(apiKeyRepo, nil, newExpiryConfigProvider(cfg), testExpiryOpts)

	apiKeyMock.ExpectQuery("SELECT.*FROM api_keys").
		WillReturnError(errors.New("db connection lost"))

	// Should log and return without panicking
	n.runCheck(context.Background())
}

func TestExpiryNotifier_RunCheck_EmptyKeys(t *testing.T) {
	apiKeyRepo, apiKeyMock := newAPIKeyRepoForNotifier(t)
	cfg := newExpiryConfig(true, "smtp.example.com")

	n := NewAPIKeyExpiryNotifier(apiKeyRepo, nil, newExpiryConfigProvider(cfg), testExpiryOpts)

	apiKeyMock.ExpectQuery("SELECT.*FROM api_keys").
		WillReturnRows(sqlmock.NewRows(findExpiringKeysCols))

	n.runCheck(context.Background()) // must not panic; empty result → early return

	if err := apiKeyMock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestExpiryNotifier_RunCheck_KeyWithNilUserID_Skipped(t *testing.T) {
	apiKeyRepo, apiKeyMock := newAPIKeyRepoForNotifier(t)
	cfg := newExpiryConfig(true, "smtp.example.com")

	n := NewAPIKeyExpiryNotifier(apiKeyRepo, nil, newExpiryConfigProvider(cfg), testExpiryOpts)

	expiresAt := time.Now().Add(3 * 24 * time.Hour)
	// user_id is NULL → key should be skipped without user lookup
	apiKeyMock.ExpectQuery("SELECT.*FROM api_keys").
		WillReturnRows(sqlmock.NewRows(findExpiringKeysCols).
			AddRow("key-1", nil, "org-1", "CI Key", nil,
				"hash", "tfr_abc", []byte(`["modules:read"]`), &expiresAt, nil, nil, time.Now()))

	n.runCheck(context.Background()) // must not panic
}

func TestExpiryNotifier_RunCheck_UserLookupError_Skipped(t *testing.T) {
	apiKeyRepo, apiKeyMock := newAPIKeyRepoForNotifier(t)
	userRepo, userMock := newUserRepoForNotifier(t)
	cfg := newExpiryConfig(true, "smtp.example.com")

	n := NewAPIKeyExpiryNotifier(apiKeyRepo, userRepo, newExpiryConfigProvider(cfg), testExpiryOpts)

	expiresAt := time.Now().Add(3 * 24 * time.Hour)
	userID := "user-1"
	apiKeyMock.ExpectQuery("SELECT.*FROM api_keys").
		WillReturnRows(sqlmock.NewRows(findExpiringKeysCols).
			AddRow("key-1", &userID, "org-1", "CI Key", nil,
				"hash", "tfr_abc", []byte(`["modules:read"]`), &expiresAt, nil, nil, time.Now()))

	// User lookup fails → key is skipped, no email sent
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnError(errors.New("user db error"))

	n.runCheck(context.Background()) // must not panic

	if err := apiKeyMock.ExpectationsWereMet(); err != nil {
		t.Errorf("api_key unmet expectations: %v", err)
	}
}

func TestExpiryNotifier_RunCheck_EmptyUserEmail_Skipped(t *testing.T) {
	apiKeyRepo, apiKeyMock := newAPIKeyRepoForNotifier(t)
	userRepo, userMock := newUserRepoForNotifier(t)
	cfg := newExpiryConfig(true, "smtp.example.com")

	n := NewAPIKeyExpiryNotifier(apiKeyRepo, userRepo, newExpiryConfigProvider(cfg), testExpiryOpts)

	expiresAt := time.Now().Add(3 * 24 * time.Hour)
	userID := "user-1"
	apiKeyMock.ExpectQuery("SELECT.*FROM api_keys").
		WillReturnRows(sqlmock.NewRows(findExpiringKeysCols).
			AddRow("key-1", &userID, "org-1", "CI Key", nil,
				"hash", "tfr_abc", []byte(`["modules:read"]`), &expiresAt, nil, nil, time.Now()))

	// User exists but has no email address → skip
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(userColsForNotifier).
			AddRow("user-1", "", "NoEmail User", nil, time.Now(), time.Now()))

	n.runCheck(context.Background())
}

func TestExpiryNotifier_RunCheck_AlreadyClaimed_SkipsSend(t *testing.T) {
	apiKeyRepo, apiKeyMock := newAPIKeyRepoForNotifier(t)
	userRepo, userMock := newUserRepoForNotifier(t)
	cfg := newExpiryConfig(true, "smtp.example.com")

	n := NewAPIKeyExpiryNotifier(apiKeyRepo, userRepo, newExpiryConfigProvider(cfg), testExpiryOpts)

	expiresAt := time.Now().Add(3 * 24 * time.Hour)
	userID := "user-1"
	apiKeyMock.ExpectQuery("SELECT.*FROM api_keys").
		WillReturnRows(sqlmock.NewRows(findExpiringKeysCols).
			AddRow("key-1", &userID, "org-1", "CI Key", nil,
				"hash", "tfr_abc", []byte(`["modules:read"]`), &expiresAt, nil, nil, time.Now()))
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(userColsForNotifier).
			AddRow("user-1", "ops@example.com", "Ops", nil, time.Now(), time.Now()))
	// Another replica already claimed this key: the conditional UPDATE affects 0
	// rows, so this run must skip the send (no SMTP attempt) rather than duplicate.
	apiKeyMock.ExpectExec("UPDATE api_keys SET expiry_notification_sent_at").
		WillReturnResult(sqlmock.NewResult(0, 0))

	n.runCheck(context.Background())

	if err := apiKeyMock.ExpectationsWereMet(); err != nil {
		t.Errorf("api_key unmet expectations: %v", err)
	}
	if err := userMock.ExpectationsWereMet(); err != nil {
		t.Errorf("user unmet expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Start — full loop paths (enabled + SMTP host set, exercising ticker/stop)
// ---------------------------------------------------------------------------

func TestExpiryNotifier_Start_ContextCancel(t *testing.T) {
	apiKeyRepo, apiKeyMock := newAPIKeyRepoForNotifier(t)
	cfg := newExpiryConfig(true, "smtp.example.com")

	n := NewAPIKeyExpiryNotifier(apiKeyRepo, nil, newExpiryConfigProvider(cfg), testExpiryOpts)

	// The immediate runCheck call — return empty
	apiKeyMock.ExpectQuery("SELECT.*FROM api_keys").
		WillReturnRows(sqlmock.NewRows(findExpiringKeysCols))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = n.Start(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// good
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

func TestExpiryNotifier_Start_StopChan(t *testing.T) {
	apiKeyRepo, apiKeyMock := newAPIKeyRepoForNotifier(t)
	cfg := newExpiryConfig(true, "smtp.example.com")

	n := NewAPIKeyExpiryNotifier(apiKeyRepo, nil, newExpiryConfigProvider(cfg), testExpiryOpts)

	apiKeyMock.ExpectQuery("SELECT.*FROM api_keys").
		WillReturnRows(sqlmock.NewRows(findExpiringKeysCols))

	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		_ = n.Start(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	_ = n.Stop()

	select {
	case <-done:
		// good
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after Stop()")
	}
}
