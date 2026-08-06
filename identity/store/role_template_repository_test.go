package store

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

var errRoleDB = errors.New("role template db error")

var roleTemplateCols = []string{"id", "name", "display_name", "description", "scopes", "is_system", "created_at", "updated_at"}

var sampleRoleScopes = []byte(`["admin","users:read"]`)

func newRoleTemplateRepo(t *testing.T) (*RoleTemplateRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewRoleTemplateRepository(db), mock
}

func sampleRoleTemplateRow() *sqlmock.Rows {
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	return sqlmock.NewRows(roleTemplateCols).
		AddRow(id, "admin", "Admin", nil, sampleRoleScopes, false, time.Now(), time.Now())
}

func TestListRoleTemplates_Success(t *testing.T) {
	repo, mock := newRoleTemplateRepo(t)
	mock.ExpectQuery("SELECT id.*FROM role_templates").
		WillReturnRows(sampleRoleTemplateRow())

	templates, err := repo.ListRoleTemplates(context.Background())
	if err != nil || len(templates) != 1 {
		t.Fatalf("got (%d, %v), want (1, nil)", len(templates), err)
	}
}

func TestListRoleTemplates_Empty(t *testing.T) {
	repo, mock := newRoleTemplateRepo(t)
	mock.ExpectQuery("SELECT id.*FROM role_templates").
		WillReturnRows(sqlmock.NewRows(roleTemplateCols))

	templates, err := repo.ListRoleTemplates(context.Background())
	if err != nil || len(templates) != 0 {
		t.Fatalf("got (%d, %v), want (0, nil)", len(templates), err)
	}
}

func TestListRoleTemplates_Error(t *testing.T) {
	repo, mock := newRoleTemplateRepo(t)
	mock.ExpectQuery("SELECT id.*FROM role_templates").
		WillReturnError(errRoleDB)

	if _, err := repo.ListRoleTemplates(context.Background()); err == nil {
		t.Error("expected error, got nil")
	}
}

func TestGetRoleTemplate_Found(t *testing.T) {
	repo, mock := newRoleTemplateRepo(t)
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	mock.ExpectQuery("SELECT id.*FROM role_templates.*WHERE id").
		WillReturnRows(sampleRoleTemplateRow())

	tpl, err := repo.GetRoleTemplate(context.Background(), id)
	if err != nil || tpl == nil {
		t.Fatalf("got (%v, %v), want a template", tpl, err)
	}
}

func TestGetRoleTemplate_NotFound(t *testing.T) {
	repo, mock := newRoleTemplateRepo(t)
	mock.ExpectQuery("SELECT id.*FROM role_templates.*WHERE id").
		WillReturnRows(sqlmock.NewRows(roleTemplateCols))

	tpl, err := repo.GetRoleTemplate(context.Background(), uuid.New())
	if !errors.Is(err, ErrNotFound) || tpl != nil {
		t.Fatalf("got (%v, %v), want (nil, ErrNotFound)", tpl, err)
	}
}

func TestGetRoleTemplate_Error(t *testing.T) {
	repo, mock := newRoleTemplateRepo(t)
	mock.ExpectQuery("SELECT id.*FROM role_templates.*WHERE id").
		WillReturnError(errRoleDB)

	if _, err := repo.GetRoleTemplate(context.Background(), uuid.New()); err == nil {
		t.Error("expected error, got nil")
	}
}

func TestGetRoleTemplateByName_Found(t *testing.T) {
	repo, mock := newRoleTemplateRepo(t)
	mock.ExpectQuery("SELECT id.*FROM role_templates.*WHERE name").
		WillReturnRows(sampleRoleTemplateRow())

	tpl, err := repo.GetRoleTemplateByName(context.Background(), "admin")
	if err != nil || tpl == nil {
		t.Fatalf("got (%v, %v), want a template", tpl, err)
	}
}

func TestGetRoleTemplateByName_NotFound(t *testing.T) {
	repo, mock := newRoleTemplateRepo(t)
	mock.ExpectQuery("SELECT id.*FROM role_templates.*WHERE name").
		WillReturnRows(sqlmock.NewRows(roleTemplateCols))

	tpl, err := repo.GetRoleTemplateByName(context.Background(), "unknown")
	if !errors.Is(err, ErrNotFound) || tpl != nil {
		t.Fatalf("got (%v, %v), want (nil, ErrNotFound)", tpl, err)
	}
}

func TestCreateRoleTemplate_Success(t *testing.T) {
	repo, mock := newRoleTemplateRepo(t)
	mock.ExpectExec("INSERT INTO role_templates").
		WillReturnResult(sqlmock.NewResult(1, 1))

	tpl := &models.RoleTemplate{
		ID:          uuid.New(),
		Name:        "custom",
		DisplayName: "Custom Role",
		Scopes:      []string{"modules:read"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	if err := repo.CreateRoleTemplate(context.Background(), tpl); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateRoleTemplate_Error(t *testing.T) {
	repo, mock := newRoleTemplateRepo(t)
	mock.ExpectExec("INSERT INTO role_templates").
		WillReturnError(errRoleDB)

	tpl := &models.RoleTemplate{ID: uuid.New(), Name: "x", Scopes: []string{}}
	if err := repo.CreateRoleTemplate(context.Background(), tpl); err == nil {
		t.Error("expected error, got nil")
	}
}

func TestUpdateRoleTemplate_Success(t *testing.T) {
	repo, mock := newRoleTemplateRepo(t)
	mock.ExpectExec("UPDATE role_templates").
		WillReturnResult(sqlmock.NewResult(1, 1))

	tpl := &models.RoleTemplate{
		ID:          uuid.New(),
		DisplayName: "Updated",
		Scopes:      []string{"providers:read"},
	}
	if err := repo.UpdateRoleTemplate(context.Background(), tpl); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteRoleTemplate_Success(t *testing.T) {
	repo, mock := newRoleTemplateRepo(t)
	mock.ExpectExec("DELETE FROM role_templates").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.DeleteRoleTemplate(context.Background(), uuid.New()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateRoleTemplate_NotFoundOrSystem(t *testing.T) {
	repo, mock := newRoleTemplateRepo(t)
	// Zero rows affected (id absent or is_system=true) must error, not no-op.
	mock.ExpectExec("UPDATE role_templates").
		WillReturnResult(sqlmock.NewResult(0, 0))

	tpl := &models.RoleTemplate{ID: uuid.New(), DisplayName: "x", Scopes: []string{"a:read"}}
	if err := repo.UpdateRoleTemplate(context.Background(), tpl); err == nil {
		t.Fatal("expected an error when no row was updated, got nil")
	}
}

func TestDeleteRoleTemplate_NotFoundOrSystem(t *testing.T) {
	repo, mock := newRoleTemplateRepo(t)
	mock.ExpectExec("DELETE FROM role_templates").
		WillReturnResult(sqlmock.NewResult(0, 0))

	if err := repo.DeleteRoleTemplate(context.Background(), uuid.New()); err == nil {
		t.Fatal("expected an error when no row was deleted, got nil")
	}
}
