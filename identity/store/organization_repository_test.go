package store

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/sethbacon/terraform-suite-identity/identity/auth"
	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

var orgCols = []string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}
var orgMemberCols = []string{"organization_id", "user_id", "role_template_id", "created_at"}
var orgMembersWithUserCols = []string{
	"organization_id", "user_id", "role_template_id", "created_at",
	"user_name", "user_email",
	"role_template_name", "role_template_display_name", "role_template_scopes",
}
var orgCreateCols = []string{"id", "created_at", "updated_at"}

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

func sampleOrgRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgCols).
		AddRow("org-1", "default", "Default Org", nil, nil, time.Now(), time.Now())
}

func emptyOrgRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgCols)
}

func sampleOrgMemberRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgMemberCols).
		AddRow("org-1", "user-1", nil, time.Now())
}

func emptyOrgMemberRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgMemberCols)
}

func newOrgRepo(t *testing.T) (*OrganizationRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewOrganizationRepository(db), mock
}

// ---------------------------------------------------------------------------
// GetByName / GetDefaultOrganization
// ---------------------------------------------------------------------------

func TestGetByName_Found(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WithArgs("default").
		WillReturnRows(sampleOrgRow())

	org, err := repo.GetByName(context.Background(), "default", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if org == nil {
		t.Fatal("expected org, got nil")
	}
	if org.Name != "default" {
		t.Errorf("Name = %s, want default", org.Name)
	}
}

func TestGetByName_NotFound(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(emptyOrgRow())

	org, err := repo.GetByName(context.Background(), "missing", OrgScopeAllOrganizations())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if org != nil {
		t.Error("expected nil, got non-nil")
	}
}

func TestGetDefaultOrganization_Found(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WithArgs("default").
		WillReturnRows(sampleOrgRow())

	org, err := repo.GetDefaultOrganization(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if org == nil {
		t.Fatal("expected org, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetByID
// ---------------------------------------------------------------------------

func TestGetByID_Found(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WithArgs("org-1").
		WillReturnRows(sampleOrgRow())

	org, err := repo.GetByID(context.Background(), "org-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if org == nil {
		t.Fatal("expected org, got nil")
	}
}

func TestGetByID_NotFound(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WillReturnRows(emptyOrgRow())

	org, err := repo.GetByID(context.Background(), "missing", OrgScopeAllOrganizations())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if org != nil {
		t.Error("expected nil, got non-nil")
	}
}

// ---------------------------------------------------------------------------
// Create (CreateOrganization)
// ---------------------------------------------------------------------------

func TestCreateOrganization_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("INSERT INTO organizations").
		WillReturnRows(sqlmock.NewRows(orgCreateCols).AddRow("org-new", time.Now(), time.Now()))

	org := &models.Organization{Name: "new-org", DisplayName: "New Org"}
	if err := repo.Create(context.Background(), org); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if org.ID != "org-new" {
		t.Errorf("ID = %s, want org-new", org.ID)
	}
}

func TestCreateOrganization_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("INSERT INTO organizations").
		WillReturnError(errDB)

	org := &models.Organization{Name: "new-org", DisplayName: "New Org"}
	if err := repo.Create(context.Background(), org); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Update / Delete
// ---------------------------------------------------------------------------

func TestUpdateOrganization_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectExec("UPDATE organizations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	org := &models.Organization{ID: "org-1", Name: "default", DisplayName: "Updated"}
	if err := repo.Update(context.Background(), org, OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteOrganization_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectExec("DELETE FROM organizations").
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Delete(context.Background(), "org-1", OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// List / Count / Search
// ---------------------------------------------------------------------------

func TestListOrgs_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*ORDER BY.*LIMIT").
		WillReturnRows(sampleOrgRow())

	orgs, err := repo.List(context.Background(), 20, 0, OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(orgs) != 1 {
		t.Errorf("len(orgs) = %d, want 1", len(orgs))
	}
}

func TestCountOrgs_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT COUNT.*FROM organizations").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

	count, err := repo.Count(context.Background(), OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
}

func TestSearchOrgs_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*WHERE.*ILIKE").
		WillReturnRows(sampleOrgRow())

	orgs, err := repo.Search(context.Background(), "default", 20, 0, OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(orgs) != 1 {
		t.Errorf("len(orgs) = %d, want 1", len(orgs))
	}
}

// ---------------------------------------------------------------------------
// GetMember / AddMember / RemoveMember
// ---------------------------------------------------------------------------

func TestGetMember_Found(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sampleOrgMemberRow())

	m, err := repo.GetMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected member, got nil")
	}
}

func TestGetMember_NotFound(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(emptyOrgMemberRow())

	m, err := repo.GetMember(context.Background(), "org-1", "user-2", OrgScopeAllOrganizations())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if m != nil {
		t.Error("expected nil, got non-nil")
	}
}

func TestRemoveMember_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectExec("DELETE FROM organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.RemoveMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ListMembersWithUsers
// ---------------------------------------------------------------------------

func TestListMembersWithUsers_Empty(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN users").
		WillReturnRows(sqlmock.NewRows(orgMembersWithUserCols))

	members, err := repo.ListMembersWithUsers(context.Background(), "org-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(members) != 0 {
		t.Errorf("len(members) = %d, want 0", len(members))
	}
}

func TestListMembersWithUsers_WithMember(t *testing.T) {
	repo, mock := newOrgRepo(t)

	scopesJSON := []byte(`["admin:read"]`)
	rows := sqlmock.NewRows(orgMembersWithUserCols).
		AddRow("org-1", "user-1", nil, time.Now(), "Alice", "alice@example.com", nil, nil, scopesJSON)
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN users").
		WillReturnRows(rows)

	members, err := repo.ListMembersWithUsers(context.Background(), "org-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(members) != 1 {
		t.Errorf("len(members) = %d, want 1", len(members))
	}
	if members[0].UserName != "Alice" {
		t.Errorf("UserName = %s, want Alice", members[0].UserName)
	}
}

// ---------------------------------------------------------------------------
// GetUserOrganizations
// ---------------------------------------------------------------------------

func TestGetUserOrganizations_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*JOIN organization_members").
		WillReturnRows(sampleOrgRow())

	orgs, err := repo.GetUserOrganizations(context.Background(), "user-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(orgs) != 1 {
		t.Errorf("len(orgs) = %d, want 1", len(orgs))
	}
}

// ---------------------------------------------------------------------------
// UpdateMemberRoleTemplate
// ---------------------------------------------------------------------------

// Re-pointed from the removed UpdateMember(*models.OrganizationMember) alias,
// which delegated here. The struct-taking name promised a whole-member update
// and delivered a role-template-only one, so the explicit signature is the one
// that survives.
func TestUpdateMemberRoleTemplate_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectExec("UPDATE organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UpdateMemberRoleTemplate(context.Background(), "org-1", "user-1", nil, OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// AddMemberWithRoleTemplate
// ---------------------------------------------------------------------------

func TestAddMemberWithRoleTemplate_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.AddMemberWithRoleTemplate(context.Background(), "org-1", "user-1", nil, OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddMemberWithRoleTemplate_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnError(errDB)

	err := repo.AddMemberWithRoleTemplate(context.Background(), "org-1", "user-1", nil, OrgScopeAllOrganizations())
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetMemberWithRole
// ---------------------------------------------------------------------------

var orgMemberWithRoleRepoCols = []string{
	"organization_id", "user_id", "role_template_id", "created_at",
	"user_name", "user_email", "role_template_name", "role_template_display_name", "role_template_scopes",
}

func sampleMemberWithRoleRepoRow() *sqlmock.Rows {
	return sqlmock.NewRows(orgMemberWithRoleRepoCols).AddRow(
		"org-1", "user-1", nil, time.Now(),
		"Alice", "alice@example.com",
		"viewer", "Viewer", []byte(`["modules:read"]`),
	)
}

func TestGetMemberWithRole_NotFound(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members").
		WillReturnRows(sqlmock.NewRows(orgMemberWithRoleRepoCols))

	m, err := repo.GetMemberWithRole(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if m != nil {
		t.Errorf("expected nil, got %v", m)
	}
}

func TestGetMemberWithRole_Found(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members").
		WillReturnRows(sampleMemberWithRoleRepoRow())

	m, err := repo.GetMemberWithRole(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected member, got nil")
	}
	if m.UserName != "Alice" {
		t.Errorf("user_name = %q, want Alice", m.UserName)
	}
}

// ---------------------------------------------------------------------------
// ListMembers
// ---------------------------------------------------------------------------

var orgMemberRepoCols = []string{"organization_id", "user_id", "role_template_id", "created_at"}

func TestListMembers_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sqlmock.NewRows(orgMemberRepoCols).
			AddRow("org-1", "user-1", nil, time.Now()))

	members, err := repo.ListMembers(context.Background(), "org-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(members) != 1 {
		t.Errorf("len(members) = %d, want 1", len(members))
	}
}

func TestListMembers_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnError(errDB)

	_, err := repo.ListMembers(context.Background(), "org-1", OrgScopeAllOrganizations())
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// AddMemberWithParams
// ---------------------------------------------------------------------------

func TestAddMemberWithParams_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	// Lookup role template by name
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WithArgs("viewer").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-1"))
	// Insert org member
	mock.ExpectExec("INSERT INTO organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.AddMemberWithParams(context.Background(), "org-1", "user-1", "viewer", OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddMemberWithParams_TemplateNotFound(t *testing.T) {
	repo, mock := newOrgRepo(t)
	// An unresolved role name must error rather than adding a scope-less member.
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WithArgs("nonexistent").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	if err := repo.AddMemberWithParams(context.Background(), "org-1", "user-1", "nonexistent", OrgScopeAllOrganizations()); err == nil {
		t.Fatal("expected an error for an unknown role template, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected DB calls (should not have inserted): %v", err)
	}
}

func TestUpdateMemberRole_TemplateNotFound(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WithArgs("nonexistent").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	if err := repo.UpdateMemberRole(context.Background(), "org-1", "user-1", "nonexistent", OrgScopeAllOrganizations()); err == nil {
		t.Fatal("expected an error for an unknown role template, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected DB calls (should not have updated): %v", err)
	}
}

func TestAddMemberWithParams_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WillReturnError(errDB)

	if err := repo.AddMemberWithParams(context.Background(), "org-1", "user-1", "viewer", OrgScopeAllOrganizations()); err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// UpdateMemberRole
// ---------------------------------------------------------------------------

func TestUpdateMemberRole_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WithArgs("admin").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-2"))
	mock.ExpectExec("UPDATE organization_members SET role_template_id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.UpdateMemberRole(context.Background(), "org-1", "user-1", "admin", OrgScopeAllOrganizations()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateMemberRole_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WillReturnError(errDB)

	if err := repo.UpdateMemberRole(context.Background(), "org-1", "user-1", "admin", OrgScopeAllOrganizations()); err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// CheckMembership
// ---------------------------------------------------------------------------

func TestCheckMembership_NotMember(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sqlmock.NewRows(orgMemberRepoCols))

	isMember, roleID, err := repo.CheckMembership(context.Background(), "org-1", "user-99", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if isMember {
		t.Error("expected not a member")
	}
	if roleID != nil {
		t.Error("expected nil roleID")
	}
}

func TestCheckMembership_IsMember(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sqlmock.NewRows(orgMemberRepoCols).AddRow("org-1", "user-1", nil, time.Now()))

	isMember, _, err := repo.CheckMembership(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isMember {
		t.Error("expected member")
	}
}

// ---------------------------------------------------------------------------
// GetUserOrganizations — failure path
// ---------------------------------------------------------------------------

// Re-pointed from the removed ListUserOrganizations alias, whose test set was
// the only one covering this accessor's query-error path; the canonical name
// had a success case only.
func TestGetUserOrganizations_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organizations.*organization_members").
		WillReturnError(errDB)

	_, err := repo.GetUserOrganizations(context.Background(), "user-1", OrgScopeAllOrganizations())
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetUserMemberships
// ---------------------------------------------------------------------------

var userMembershipCols = []string{
	"organization_id", "organization_name",
	"role_template_id", "created_at",
	"role_template_name", "role_template_display_name", "role_template_scopes",
}

func TestGetUserMemberships_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WillReturnRows(sqlmock.NewRows(userMembershipCols).AddRow(
			"org-1", "default", nil, time.Now(),
			"viewer", "Viewer", []byte(`["modules:read"]`),
		))

	memberships, err := repo.GetUserMemberships(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(memberships) != 1 {
		t.Errorf("len = %d, want 1", len(memberships))
	}
	if memberships[0].OrganizationName != "default" {
		t.Errorf("org name = %q, want default", memberships[0].OrganizationName)
	}
}

func TestGetUserMemberships_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WillReturnError(errDB)

	_, err := repo.GetUserMemberships(context.Background(), "user-1")
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetUserCombinedScopes
// ---------------------------------------------------------------------------

func TestGetUserCombinedScopes_Success(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WillReturnRows(sqlmock.NewRows(userMembershipCols).AddRow(
			"org-1", "default", nil, time.Now(),
			"viewer", "Viewer", []byte(`["modules:read","modules:write"]`),
		))

	scopes, err := repo.GetUserCombinedScopes(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scopes) == 0 {
		t.Error("expected scopes, got empty")
	}
}

func TestGetUserCombinedScopes_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WillReturnError(errDB)

	_, err := repo.GetUserCombinedScopes(context.Background(), "user-1")
	if err == nil {
		t.Error("expected error")
	}
}

func TestGetUserCombinedScopes_UnionsAcrossDistinctOrganizations(t *testing.T) {
	// GetUserCombinedScopes is the ONLY scope primitive: it unions a user's
	// scopes across ALL org memberships into one flat set fed to the JWT. This
	// pins the union/dedup contract with two DIFFERENT organizations rather
	// than the single-row case TestGetUserCombinedScopes_Success covers.
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WillReturnRows(sqlmock.NewRows(userMembershipCols).
			AddRow("org-1", "acme", nil, time.Now(),
				"viewer", "Viewer", []byte(`["modules:read","shared:read"]`)).
			AddRow("org-2", "widgets", nil, time.Now(),
				"editor", "Editor", []byte(`["modules:write","shared:read"]`)))

	scopes, err := repo.GetUserCombinedScopes(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		got[s] = true
	}
	want := []string{"modules:read", "modules:write", "shared:read"}
	if len(got) != len(want) {
		t.Fatalf("scopes = %v, want exactly %v (union of both orgs, deduplicated)", scopes, want)
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing expected scope %q in union result %v", w, scopes)
		}
	}
}

// ---------------------------------------------------------------------------
// GetUserScopesForOrg
// ---------------------------------------------------------------------------

func TestGetUserScopesForOrg_Found(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members").
		WithArgs("org-1", "user-1").
		WillReturnRows(sqlmock.NewRows(orgMemberWithRoleRepoCols).AddRow(
			"org-1", "user-1", nil, time.Now(),
			"Alice", "alice@example.com",
			"admin", "Admin", []byte(`["modules:read","modules:write"]`),
		))

	scopes, err := repo.GetUserScopesForOrg(context.Background(), "user-1", "org-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		got[s] = true
	}
	want := []string{"modules:read", "modules:write"}
	if len(got) != len(want) {
		t.Fatalf("scopes = %v, want exactly %v", scopes, want)
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing expected scope %q in result %v", w, scopes)
		}
	}
}

func TestGetUserScopesForOrg_NotFound(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members").
		WithArgs("org-1", "user-1").
		WillReturnRows(sqlmock.NewRows(orgMemberWithRoleRepoCols))

	scopes, err := repo.GetUserScopesForOrg(context.Background(), "user-1", "org-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scopes) != 0 {
		t.Errorf("scopes = %v, want empty", scopes)
	}
}

func TestGetUserScopesForOrg_DBError(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members").
		WithArgs("org-1", "user-1").
		WillReturnError(errDB)

	_, err := repo.GetUserScopesForOrg(context.Background(), "user-1", "org-1")
	if err == nil {
		t.Error("expected error")
	}
}

func TestGetUserScopesForOrg_ExcludesOtherOrgScopes(t *testing.T) {
	// This is the key regression test for issue #54: GetUserCombinedScopes unions scopes
	// across ALL of a user's org memberships into one flat, org-less set. A user who is
	// admin in org-1 and viewer in org-2 must NOT have org-2's (or org-1's) scopes leak
	// into a lookup scoped to the OTHER organization. GetUserScopesForOrg must resolve
	// scopes for exactly one target organization at a time.
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members").
		WithArgs("org-1", "user-1").
		WillReturnRows(sqlmock.NewRows(orgMemberWithRoleRepoCols).AddRow(
			"org-1", "user-1", nil, time.Now(),
			"Alice", "alice@example.com",
			"admin", "Admin", []byte(`["org1:admin","shared:read"]`),
		))
	mock.ExpectQuery("SELECT.*FROM organization_members").
		WithArgs("org-2", "user-1").
		WillReturnRows(sqlmock.NewRows(orgMemberWithRoleRepoCols).AddRow(
			"org-2", "user-1", nil, time.Now(),
			"Alice", "alice@example.com",
			"viewer", "Viewer", []byte(`["org2:viewer","shared:read"]`),
		))

	org1Scopes, err := repo.GetUserScopesForOrg(context.Background(), "user-1", "org-1")
	if err != nil {
		t.Fatalf("unexpected error for org-1: %v", err)
	}
	for _, s := range org1Scopes {
		if s == "org2:viewer" {
			t.Fatalf("org-1 scopes leaked org-2's scope: %v", org1Scopes)
		}
	}
	if len(org1Scopes) != 2 {
		t.Fatalf("org-1 scopes = %v, want exactly 2 (org1:admin, shared:read)", org1Scopes)
	}

	org2Scopes, err := repo.GetUserScopesForOrg(context.Background(), "user-1", "org-2")
	if err != nil {
		t.Fatalf("unexpected error for org-2: %v", err)
	}
	for _, s := range org2Scopes {
		if s == "org1:admin" {
			t.Fatalf("org-2 scopes leaked org-1's scope: %v", org2Scopes)
		}
	}
	if len(org2Scopes) != 2 {
		t.Fatalf("org-2 scopes = %v, want exactly 2 (org2:viewer, shared:read)", org2Scopes)
	}
}

// TestGetUserScopesForOrg_EndToEndWithJWT is the full-chain regression test for issue #54:
// it exercises the entire recommended safe path — GetUserScopesForOrg (this package) feeding
// auth.TokenManager.GenerateForOrg, verified by auth.Validate + auth.HasScopeInOrg — for a
// user who is admin in org-1 and only a viewer in org-2, and proves the org-1 admin token
// cannot authorize an org-2 action, while it can authorize the equivalent org-1 action.
// Contrast this with the legacy GetUserCombinedScopes + Generate + HasScope path, which
// (by design, per its documented warning) would authorize the org-2 action too.
func TestGetUserScopesForOrg_EndToEndWithJWT(t *testing.T) {
	repo, mock := newOrgRepo(t)
	mock.ExpectQuery("SELECT.*FROM organization_members").
		WithArgs("org-1", "user-1").
		WillReturnRows(sqlmock.NewRows(orgMemberWithRoleRepoCols).AddRow(
			"org-1", "user-1", nil, time.Now(),
			"Alice", "alice@example.com",
			"admin", "Admin", []byte(`["admin"]`),
		))

	orgScopes, err := repo.GetUserScopesForOrg(context.Background(), "user-1", "org-1")
	if err != nil {
		t.Fatalf("GetUserScopesForOrg: %v", err)
	}

	tm := auth.NewTokenManager("test-secret-key-that-is-long-enough-32+", "test-issuer")
	tok, err := tm.GenerateForOrg("user-1", "alice@example.com", "org-1", orgScopes, time.Hour)
	if err != nil {
		t.Fatalf("GenerateForOrg: %v", err)
	}
	claims, err := tm.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// The org-1 admin token must authorize an org-1 action...
	if !auth.HasScopeInOrg(claims, "org-1", auth.ScopeUsersRead, nil) {
		t.Fatal("expected org-1 admin token to authorize an org-1 action")
	}
	// ...but must NOT authorize the equivalent action against org-2, even though
	// the token carries the "admin" scope — this is the exact cross-org
	// escalation issue #54 describes, and GenerateForOrg + HasScopeInOrg (unlike
	// Generate + HasScope on a flat combined-scope set) close it.
	if auth.HasScopeInOrg(claims, "org-2", auth.ScopeUsersRead, nil) {
		t.Fatal("org-1 admin token must not authorize an org-2 action")
	}
}

// ---------------------------------------------------------------------------
// GetDefaultOrganization cache hit path
// ---------------------------------------------------------------------------

func TestGetDefaultOrganization_CacheHit(t *testing.T) {
	repo, mock := newOrgRepo(t)

	// First call hits the DB and populates the cache.
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WithArgs("default").
		WillReturnRows(sampleOrgRow())

	org1, err := repo.GetDefaultOrganization(context.Background())
	if err != nil {
		t.Fatalf("first call unexpected error: %v", err)
	}
	if org1 == nil {
		t.Fatal("first call: expected org, got nil")
	}

	// Second call should return from cache — no new DB query expected.
	org2, err := repo.GetDefaultOrganization(context.Background())
	if err != nil {
		t.Fatalf("second call unexpected error: %v", err)
	}
	if org2 == nil {
		t.Fatal("second call: expected org, got nil")
	}
	if org1.ID != org2.ID {
		t.Errorf("cache returned different ID: %q vs %q", org1.ID, org2.ID)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (extra DB query occurred): %v", err)
	}
}
