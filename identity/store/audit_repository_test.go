package store

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

// auditCols mirrors the SELECT in ListAuditLogs and StreamAuditLogs: ten stored
// columns, then the two the LEFT JOIN on users supplies. actor_email is STORED
// (it is the actor retained on the row, which is what survives a user delete —
// issue #142) and so sits with the stored columns, before the joined pair.
var auditCols = []string{
	"id", "user_id", "organization_id", "action",
	"resource_type", "resource_id", "metadata", "ip_address", "created_at", "actor_email",
	"user_email", "user_name",
}

// auditGetCols mirrors the SELECT in GetAuditLog (10 stored columns, no JOIN fields).
var auditGetCols = []string{
	"id", "user_id", "organization_id", "action",
	"resource_type", "resource_id", "metadata", "ip_address", "created_at", "actor_email",
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newAuditRepo(t *testing.T) (*AuditRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewAuditRepository(db), mock
}

func sampleAuditRow() *sqlmock.Rows {
	return sqlmock.NewRows(auditCols).
		AddRow("log-1", "user-1", "org-1", "CREATE",
			"module", "module-1", []byte(`{"key":"val"}`), "1.2.3.4", time.Now(),
			"actor@example.test", nil, nil)
}

func sampleAuditGetRow() *sqlmock.Rows {
	return sqlmock.NewRows(auditGetCols).
		AddRow("log-1", "user-1", "org-1", "CREATE",
			"module", "module-1", []byte(`{"key":"val"}`), "1.2.3.4", time.Now(),
			"actor@example.test")
}

// createdAuditRow is what the INSERT's RETURNING clause hands back: the
// actor_email the database resolved (or the caller supplied).
func createdAuditRow(actorEmail interface{}) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"actor_email"}).AddRow(actorEmail)
}

// ---------------------------------------------------------------------------
// CreateAuditLog
// ---------------------------------------------------------------------------

func strPtr(s string) *string { return &s }

func TestCreateAuditLog_Success(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery("INSERT INTO audit_logs").
		WillReturnRows(createdAuditRow("resolved@example.test"))

	log := &models.AuditLog{
		UserID:         strPtr("user-1"),
		OrganizationID: strPtr("org-1"),
		Action:         "CREATE",
		ResourceType:   strPtr("module"),
		ResourceID:     strPtr("module-1"),
		IPAddress:      strPtr("1.2.3.4"),
	}
	if err := repo.CreateAuditLog(context.Background(), log); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The caller left ActorEmail nil, so what the statement resolved has to come
	// back on the struct — otherwise the write path can silently stop retaining
	// the actor and nothing in-process would notice.
	if log.ActorEmail == nil || *log.ActorEmail != "resolved@example.test" {
		t.Errorf("ActorEmail = %v, want the address the INSERT resolved", log.ActorEmail)
	}
}

// TestCreateAuditLog_ResolvesTheActorInTheInsert pins the shape of the statement,
// not just its effect: the actor is resolved by a sub-select inside the INSERT.
// A second round trip would be a different (and racier) design, and reverting to
// a plain INSERT would silently stop retaining attribution.
func TestCreateAuditLog_ResolvesTheActorInTheInsert(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery(`INSERT INTO audit_logs.*actor_email.*SELECT email FROM users WHERE id`).
		WillReturnRows(createdAuditRow("resolved@example.test"))

	if err := repo.CreateAuditLog(context.Background(), &models.AuditLog{
		UserID: strPtr("user-1"),
		Action: "CREATE",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("CreateAuditLog no longer resolves the actor inside the INSERT: %v", err)
	}
}

// TestCreateAuditLog_CallerSuppliedActorWins covers the federated case: an entry
// whose actor has no users row in THIS database still has to arrive attributed.
func TestCreateAuditLog_CallerSuppliedActorWins(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery("INSERT INTO audit_logs").
		WithArgs(sqlmock.AnyArg(), strPtr("user-1"), nil, "CREATE", nil, nil, nil, nil,
			sqlmock.AnyArg(), strPtr("sibling@example.test")).
		WillReturnRows(createdAuditRow("sibling@example.test"))

	log := &models.AuditLog{
		UserID:     strPtr("user-1"),
		Action:     "CREATE",
		ActorEmail: strPtr("sibling@example.test"),
	}
	if err := repo.CreateAuditLog(context.Background(), log); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the caller-supplied actor did not reach the statement: %v", err)
	}
}

func TestCreateAuditLog_WithMetadata(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery("INSERT INTO audit_logs").
		WillReturnRows(createdAuditRow(nil))

	log := &models.AuditLog{
		UserID:       strPtr("user-1"),
		Action:       "UPDATE",
		ResourceType: strPtr("provider"),
		Metadata:     map[string]interface{}{"version": "1.0.0"},
	}
	if err := repo.CreateAuditLog(context.Background(), log); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateAuditLog_DBError(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery("INSERT INTO audit_logs").
		WillReturnError(errDB)

	log := &models.AuditLog{Action: "CREATE"}
	if err := repo.CreateAuditLog(context.Background(), log); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ListAuditLogs
// ---------------------------------------------------------------------------

func TestListAuditLogs_NoFilters(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery("SELECT COUNT.*FROM audit_logs").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT al\\.id.*FROM audit_logs").
		WillReturnRows(sampleAuditRow())

	logs, total, err := repo.ListAuditLogs(context.Background(), AuditFilters{}, OrgScopeAllOrganizations(), 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(logs) != 1 {
		t.Errorf("len(logs) = %d, want 1", len(logs))
	}
}

func TestListAuditLogs_WithFilters(t *testing.T) {
	repo, mock := newAuditRepo(t)
	userID := "user-1"
	orgID := "org-1"
	action := "CREATE"
	resourceType := "module"

	mock.ExpectQuery("SELECT COUNT.*FROM audit_logs").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT al\\.id.*FROM audit_logs").
		WillReturnRows(sqlmock.NewRows(auditCols))

	logs, total, err := repo.ListAuditLogs(context.Background(), AuditFilters{
		UserID:         &userID,
		OrganizationID: &orgID,
		Action:         &action,
		ResourceType:   &resourceType,
	}, OrgScopeAllOrganizations(), 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 0 {
		t.Errorf("total = %d, want 0", total)
	}
	if len(logs) != 0 {
		t.Errorf("len(logs) = %d, want 0", len(logs))
	}
}

func TestListAuditLogs_CountError(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery("SELECT COUNT.*FROM audit_logs").
		WillReturnError(errDB)

	_, _, err := repo.ListAuditLogs(context.Background(), AuditFilters{}, OrgScopeAllOrganizations(), 10, 0)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestListAuditLogs_QueryError(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery("SELECT COUNT.*FROM audit_logs").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT al\\.id.*FROM audit_logs").
		WillReturnError(errDB)

	_, _, err := repo.ListAuditLogs(context.Background(), AuditFilters{}, OrgScopeAllOrganizations(), 10, 0)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetAuditLog
// ---------------------------------------------------------------------------

func TestGetAuditLog_Found(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery("SELECT id.*FROM audit_logs.*WHERE id").
		WillReturnRows(sampleAuditGetRow())

	log, err := repo.GetAuditLog(context.Background(), "log-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if log == nil {
		t.Fatal("expected log, got nil")
	}
	if log.ID != "log-1" {
		t.Errorf("ID = %q, want %q", log.ID, "log-1")
	}
}

func TestGetAuditLog_NotFound(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery("SELECT id.*FROM audit_logs.*WHERE id").
		WillReturnRows(sqlmock.NewRows(auditGetCols))

	log, err := repo.GetAuditLog(context.Background(), "missing", OrgScopeAllOrganizations())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if log != nil {
		t.Errorf("expected nil, got %v", log)
	}
}

func TestGetAuditLog_Error(t *testing.T) {
	repo, mock := newAuditRepo(t)
	mock.ExpectQuery("SELECT id.*FROM audit_logs.*WHERE id").
		WillReturnError(errDB)

	_, err := repo.GetAuditLog(context.Background(), "log-1", OrgScopeAllOrganizations())
	if err == nil {
		t.Error("expected error, got nil")
	}
}
