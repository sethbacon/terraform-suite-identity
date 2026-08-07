// notfound_class_test.go is the CLASS TEST for "not-found is indistinguishable
// from success" (issues #67 and #155).
//
// The class has three members, and each is asserted here as a table rather than
// one test per accessor, because the defect is a MISSING check and a missing
// check is only visible when every member of the class is swept together:
//
//  1. A read that matched no row returned (nil, nil), so the idiomatic
//     `x, err := Get(); if err != nil { return err }; use(x.F)` panicked on a
//     miss instead of denying the request.
//  2. A by-identifier UPDATE/DELETE that matched no row returned nil — success.
//     A revocation, a member removal, a role change or an organization delete
//     that touched nothing was reported to an operator, and written to an audit
//     log, as though it had happened.
//  3. A bulk sweep reported nothing at all, so "cleaned 4000 rows" and "did
//     nothing" were the same result.
//
// This batch has NO COMPILE FORCING FUNCTION: `return nil, nil` becoming
// `return nil, ErrNotFound` changes no signature, and mutators already returned
// error. Every consumer call site compiles unchanged. That is exactly why the
// two structural guards at the bottom of this file exist — they are what stops a
// NEW accessor from quietly rejoining the class, since nothing else in the build
// would notice.
//
// Both directions are asserted throughout. A table that only checks that a miss
// errors would still pass if every accessor errored on everything, which is the
// failure mode that would take an application down hardest.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// classRepos holds every repository in the package over ONE mock connection, so
// a single table can sweep accessors that live on different types.
type classRepos struct {
	users  *UserRepository
	orgs   *OrganizationRepository
	keys   *APIKeyRepository
	oidc   *OIDCConfigRepository
	roles  *RoleTemplateRepository
	audit  *AuditRepository
	tokens *TokenRepository
}

func newClassRepos(t *testing.T) (*classRepos, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &classRepos{
		users:  NewUserRepository(db),
		orgs:   NewOrganizationRepository(db),
		keys:   NewAPIKeyRepository(db),
		oidc:   NewOIDCConfigRepository(db),
		roles:  NewRoleTemplateRepository(db),
		audit:  NewAuditRepository(db),
		tokens: NewTokenRepository(db),
	}, mock
}

// ---------------------------------------------------------------------------
// Member 1: reads
// ---------------------------------------------------------------------------

// notFoundReadAxis is one read accessor that can miss.
//
// primeHit and primeMiss install the SAME statement expectations and differ only
// in whether a row comes back, so the two directions exercise one code path and
// the assertion is genuinely about the miss rather than about the SQL.
type notFoundReadAxis struct {
	name      string
	primeHit  func(mock sqlmock.Sqlmock)
	primeMiss func(mock sqlmock.Sqlmock)
	// call returns whether the accessor produced a non-nil value, plus its error.
	call func(r *classRepos) (gotValue bool, err error)
}

func notFoundReadAxes() []notFoundReadAxis {
	oidcRow := func() *sqlmock.Rows {
		now := time.Now()
		return sqlmock.NewRows(oidcConfigCols).AddRow(
			uuid.New(), "default", "generic_oidc", "https://issuer.example.com", "client-id",
			"encrypted-secret", "https://app/callback", []byte(`["openid"]`), true,
			[]byte(`{}`), now, now, nil, nil,
		)
	}
	membershipRow := func() *sqlmock.Rows {
		return sqlmock.NewRows(userMembershipCols).
			AddRow("org-1", "default", nil, time.Now(), "viewer", "Viewer", []byte(`["modules:read"]`))
	}

	return []notFoundReadAxis{
		{
			name:      "UserRepository.GetUserByID",
			primeHit:  func(m sqlmock.Sqlmock) { m.ExpectQuery("SELECT.*FROM users.*WHERE id").WillReturnRows(sampleUserRow()) },
			primeMiss: func(m sqlmock.Sqlmock) { m.ExpectQuery("SELECT.*FROM users.*WHERE id").WillReturnRows(emptyUserRow()) },
			call: func(r *classRepos) (bool, error) {
				u, err := r.users.GetUserByID(context.Background(), "user-1", OrgScopeAllOrganizations())
				return u != nil, err
			},
		},
		{
			name: "UserRepository.GetUserByEmail",
			primeHit: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM users.*WHERE email").WillReturnRows(sampleUserRow())
			},
			primeMiss: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM users.*WHERE email").WillReturnRows(emptyUserRow())
			},
			call: func(r *classRepos) (bool, error) {
				u, err := r.users.GetUserByEmail(context.Background(), "a@example.com")
				return u != nil, err
			},
		},
		{
			name: "UserRepository.GetUserByOIDCSub",
			primeHit: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").WillReturnRows(sampleUserRow())
			},
			primeMiss: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").WillReturnRows(emptyUserRow())
			},
			call: func(r *classRepos) (bool, error) {
				u, err := r.users.GetUserByOIDCSub(context.Background(), "sub-1")
				return u != nil, err
			},
		},
		{
			name: "UserRepository.GetUserWithOrgRoles",
			primeHit: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM users.*WHERE id").WillReturnRows(sampleUserRow())
				m.ExpectQuery("FROM organization_members").WillReturnRows(membershipRow())
			},
			primeMiss: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM users.*WHERE id").WillReturnRows(emptyUserRow())
			},
			call: func(r *classRepos) (bool, error) {
				u, err := r.users.GetUserWithOrgRoles(context.Background(), "user-1", OrgScopeAllOrganizations())
				return u != nil, err
			},
		},
		{
			name: "OrganizationRepository.GetByName",
			primeHit: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM organizations WHERE name").WillReturnRows(sampleOrgRow())
			},
			primeMiss: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM organizations WHERE name").WillReturnRows(emptyOrgRow())
			},
			call: func(r *classRepos) (bool, error) {
				o, err := r.orgs.GetByName(context.Background(), "default", OrgScopeAllOrganizations())
				return o != nil, err
			},
		},
		{
			name: "OrganizationRepository.GetByID",
			primeHit: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM organizations WHERE id").WillReturnRows(sampleOrgRow())
			},
			primeMiss: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM organizations WHERE id").WillReturnRows(emptyOrgRow())
			},
			call: func(r *classRepos) (bool, error) {
				o, err := r.orgs.GetByID(context.Background(), "org-1", OrgScopeAllOrganizations())
				return o != nil, err
			},
		},
		{
			// The cached accessor delegates to GetByName; a miss must propagate
			// rather than be swallowed into a nil organization AND must not be
			// cached (asserted separately below).
			name: "OrganizationRepository.GetDefaultOrganization",
			primeHit: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM organizations WHERE name").WillReturnRows(sampleOrgRow())
			},
			primeMiss: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM organizations WHERE name").WillReturnRows(emptyOrgRow())
			},
			call: func(r *classRepos) (bool, error) {
				o, err := r.orgs.GetDefaultOrganization(context.Background())
				return o != nil, err
			},
		},
		{
			name: "OrganizationRepository.GetMember",
			primeHit: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").WillReturnRows(sampleOrgMemberRow())
			},
			primeMiss: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").WillReturnRows(emptyOrgMemberRow())
			},
			call: func(r *classRepos) (bool, error) {
				mem, err := r.orgs.GetMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations())
				return mem != nil, err
			},
		},
		{
			name: "OrganizationRepository.GetMemberWithRole",
			primeHit: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("FROM organization_members").WillReturnRows(sampleMemberWithRoleRepoRow())
			},
			primeMiss: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("FROM organization_members").WillReturnRows(sqlmock.NewRows(orgMemberWithRoleRepoCols))
			},
			call: func(r *classRepos) (bool, error) {
				mem, err := r.orgs.GetMemberWithRole(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations())
				return mem != nil, err
			},
		},
		{
			name: "APIKeyRepository.GetAPIKeyByID",
			primeHit: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM api_keys.*WHERE id").WillReturnRows(sampleAPIKeyRow())
			},
			primeMiss: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM api_keys.*WHERE id").WillReturnRows(emptyAPIKeyRow())
			},
			call: func(r *classRepos) (bool, error) {
				k, err := r.keys.GetAPIKeyByID(context.Background(), "key-1", OrgScopeAllOrganizations())
				return k != nil, err
			},
		},
		{
			name: "OIDCConfigRepository.GetActiveOIDCConfig",
			primeHit: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM oidc_config WHERE is_active").WillReturnRows(oidcRow())
			},
			primeMiss: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM oidc_config WHERE is_active").WillReturnRows(sqlmock.NewRows(oidcConfigCols))
			},
			call: func(r *classRepos) (bool, error) {
				c, err := r.oidc.GetActiveOIDCConfig(context.Background())
				return c != nil, err
			},
		},
		{
			name:     "OIDCConfigRepository.GetOIDCConfig",
			primeHit: func(m sqlmock.Sqlmock) { m.ExpectQuery("SELECT.*FROM oidc_config WHERE id").WillReturnRows(oidcRow()) },
			primeMiss: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM oidc_config WHERE id").WillReturnRows(sqlmock.NewRows(oidcConfigCols))
			},
			call: func(r *classRepos) (bool, error) {
				c, err := r.oidc.GetOIDCConfig(context.Background(), uuid.New())
				return c != nil, err
			},
		},
		{
			name: "RoleTemplateRepository.GetRoleTemplate",
			primeHit: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT id.*FROM role_templates.*WHERE id").WillReturnRows(sampleRoleTemplateRow())
			},
			primeMiss: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT id.*FROM role_templates.*WHERE id").WillReturnRows(sqlmock.NewRows(roleTemplateCols))
			},
			call: func(r *classRepos) (bool, error) {
				tpl, err := r.roles.GetRoleTemplate(context.Background(), uuid.New())
				return tpl != nil, err
			},
		},
		{
			name: "RoleTemplateRepository.GetRoleTemplateByName",
			primeHit: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT id.*FROM role_templates.*WHERE name").WillReturnRows(sampleRoleTemplateRow())
			},
			primeMiss: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT id.*FROM role_templates.*WHERE name").WillReturnRows(sqlmock.NewRows(roleTemplateCols))
			},
			call: func(r *classRepos) (bool, error) {
				tpl, err := r.roles.GetRoleTemplateByName(context.Background(), "admin")
				return tpl != nil, err
			},
		},
		{
			name: "AuditRepository.GetAuditLog",
			primeHit: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT id.*FROM audit_logs.*WHERE id").WillReturnRows(sampleAuditGetRow())
			},
			primeMiss: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT id.*FROM audit_logs.*WHERE id").WillReturnRows(sqlmock.NewRows(auditGetCols))
			},
			call: func(r *classRepos) (bool, error) {
				l, err := r.audit.GetAuditLog(context.Background(), "log-1", OrgScopeAllOrganizations())
				return l != nil, err
			},
		},
	}
}

// TestNotFoundClass_ReadMissReportsSentinel sweeps every read that can miss and
// pins that a miss is an ErrNotFound rather than a nil value with a nil error.
func TestNotFoundClass_ReadMissReportsSentinel(t *testing.T) {
	for _, axis := range notFoundReadAxes() {
		t.Run(axis.name, func(t *testing.T) {
			repos, mock := newClassRepos(t)
			axis.primeMiss(mock)

			gotValue, err := axis.call(repos)
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("%s: a miss returned err=%v, want an error wrapping ErrNotFound "+
					"(a (nil, nil) miss is a nil-dereference trap for every caller)", axis.name, err)
			}
			if gotValue {
				t.Errorf("%s: a miss returned a non-nil value alongside ErrNotFound", axis.name)
			}
			if errors.Is(err, sql.ErrNoRows) {
				t.Errorf("%s: sql.ErrNoRows escaped the repository boundary: %v", axis.name, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: %v", axis.name, err)
			}
		})
	}
}

// TestNotFoundClass_ReadHitStillSucceeds is the OTHER direction, and it is not
// decoration: without it, an accessor that returned ErrNotFound unconditionally
// would satisfy the table above.
func TestNotFoundClass_ReadHitStillSucceeds(t *testing.T) {
	for _, axis := range notFoundReadAxes() {
		t.Run(axis.name, func(t *testing.T) {
			repos, mock := newClassRepos(t)
			axis.primeHit(mock)

			gotValue, err := axis.call(repos)
			if err != nil {
				t.Fatalf("%s: a hit returned err=%v, want nil", axis.name, err)
			}
			if !gotValue {
				t.Errorf("%s: a hit returned a nil value with a nil error", axis.name)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: %v", axis.name, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Member 2: by-identifier mutations
// ---------------------------------------------------------------------------

// zeroRowMutationAxis is one by-identifier UPDATE/DELETE. prime installs the
// expectations for a statement that affects n rows, so the zero-row and one-row
// runs differ only in n.
type zeroRowMutationAxis struct {
	name  string
	prime func(mock sqlmock.Sqlmock, n int64)
	call  func(r *classRepos) error
}

func zeroRowMutationAxes() []zeroRowMutationAxis {
	exec := func(pattern string) func(sqlmock.Sqlmock, int64) {
		return func(m sqlmock.Sqlmock, n int64) {
			m.ExpectExec(pattern).WillReturnResult(sqlmock.NewResult(0, n))
		}
	}
	return []zeroRowMutationAxis{
		{
			name:  "UserRepository.UpdateUser",
			prime: exec("UPDATE users SET"),
			call: func(r *classRepos) error {
				return r.users.UpdateUser(context.Background(), &models.User{ID: "user-1"}, OrgScopeAllOrganizations())
			},
		},
		{
			name:  "UserRepository.DeleteUser",
			prime: exec("DELETE FROM users"),
			call: func(r *classRepos) error {
				return r.users.DeleteUser(context.Background(), "user-1", OrgScopeAllOrganizations())
			},
		},
		{
			name:  "APIKeyRepository.UpdateLastUsed",
			prime: exec("UPDATE api_keys"),
			call:  func(r *classRepos) error { return r.keys.UpdateLastUsed(context.Background(), "key-1") },
		},
		{
			name:  "APIKeyRepository.RevokeAPIKey",
			prime: exec("DELETE FROM api_keys"),
			call: func(r *classRepos) error {
				return r.keys.RevokeAPIKey(context.Background(), "key-1", OrgScopeAllOrganizations())
			},
		},
		{
			name:  "APIKeyRepository.Update",
			prime: exec("UPDATE api_keys"),
			call: func(r *classRepos) error {
				return r.keys.Update(context.Background(), &models.APIKey{ID: "key-1"}, OrgScopeAllOrganizations())
			},
		},
		{
			name:  "OrganizationRepository.RemoveMember",
			prime: exec("DELETE FROM organization_members"),
			call: func(r *classRepos) error {
				return r.orgs.RemoveMember(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations())
			},
		},
		{
			name:  "OrganizationRepository.UpdateMemberRoleTemplate",
			prime: exec("UPDATE organization_members"),
			call: func(r *classRepos) error {
				return r.orgs.UpdateMemberRoleTemplate(context.Background(), "org-1", "user-1", nil, OrgScopeAllOrganizations())
			},
		},
		{
			name:  "OrganizationRepository.Update",
			prime: exec("UPDATE organizations"),
			call: func(r *classRepos) error {
				return r.orgs.Update(context.Background(), &models.Organization{ID: "org-1"}, OrgScopeAllOrganizations())
			},
		},
		{
			name:  "OrganizationRepository.Rename",
			prime: exec("UPDATE organizations SET name"),
			call: func(r *classRepos) error {
				return r.orgs.Rename(context.Background(), "org-1", "new", OrgScopeAllOrganizations())
			},
		},
		{
			name:  "OrganizationRepository.Delete",
			prime: exec("DELETE FROM organizations"),
			call: func(r *classRepos) error {
				return r.orgs.Delete(context.Background(), "org-1", OrgScopeAllOrganizations())
			},
		},
		{
			name:  "OIDCConfigRepository.DeleteOIDCConfig",
			prime: exec("DELETE FROM oidc_config"),
			call:  func(r *classRepos) error { return r.oidc.DeleteOIDCConfig(context.Background(), uuid.New()) },
		},
		{
			name:  "OIDCConfigRepository.UpdateOIDCConfigExtraConfig",
			prime: exec("UPDATE oidc_config SET extra_config"),
			call: func(r *classRepos) error {
				return r.oidc.UpdateOIDCConfigExtraConfig(context.Background(), uuid.New(), []byte(`{}`))
			},
		},
		{
			// The transactional one. A zero-row activation must also ROLL BACK,
			// or the deactivate-all step commits alone and the deployment loses
			// SSO while the caller is told the activation succeeded.
			name: "OIDCConfigRepository.ActivateOIDCConfig",
			prime: func(m sqlmock.Sqlmock, n int64) {
				m.ExpectBegin()
				m.ExpectExec("UPDATE oidc_config SET is_active = false").
					WillReturnResult(sqlmock.NewResult(0, 3))
				m.ExpectExec("UPDATE oidc_config SET is_active = true").
					WillReturnResult(sqlmock.NewResult(0, n))
				if n == 0 {
					m.ExpectRollback()
				} else {
					m.ExpectCommit()
				}
			},
			call: func(r *classRepos) error { return r.oidc.ActivateOIDCConfig(context.Background(), uuid.New()) },
		},
		{
			// Already refused a zero-row update before this batch; asserted here
			// so the sweep is complete and so its error is confirmed to WRAP the
			// one sentinel rather than being its own unmatched string.
			name:  "RoleTemplateRepository.UpdateRoleTemplate",
			prime: exec("UPDATE role_templates"),
			call: func(r *classRepos) error {
				return r.roles.UpdateRoleTemplate(context.Background(), &models.RoleTemplate{ID: uuid.New()})
			},
		},
		{
			name:  "RoleTemplateRepository.DeleteRoleTemplate",
			prime: exec("DELETE FROM role_templates"),
			call:  func(r *classRepos) error { return r.roles.DeleteRoleTemplate(context.Background(), uuid.New()) },
		},
	}
}

// TestNotFoundClass_ZeroRowMutationReportsSentinel is the half of the class that
// matters most for batch 11: a tenancy predicate is only enforceable if a write
// it filters out is distinguishable from one that did the work.
func TestNotFoundClass_ZeroRowMutationReportsSentinel(t *testing.T) {
	for _, axis := range zeroRowMutationAxes() {
		t.Run(axis.name, func(t *testing.T) {
			repos, mock := newClassRepos(t)
			axis.prime(mock, 0)

			err := axis.call(repos)
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("%s: a zero-row mutation returned err=%v, want an error wrapping "+
					"ErrNotFound (nil here reports a security-state change that never happened)",
					axis.name, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: %v", axis.name, err)
			}
		})
	}
}

// TestNotFoundClass_OneRowMutationSucceeds is the other direction: a mutation
// that really did the work must still report success.
func TestNotFoundClass_OneRowMutationSucceeds(t *testing.T) {
	for _, axis := range zeroRowMutationAxes() {
		t.Run(axis.name, func(t *testing.T) {
			repos, mock := newClassRepos(t)
			axis.prime(mock, 1)

			if err := axis.call(repos); err != nil {
				t.Fatalf("%s: a one-row mutation returned err=%v, want nil", axis.name, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: %v", axis.name, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Member 3: bulk sweeps
// ---------------------------------------------------------------------------

type bulkSweepAxis struct {
	name  string
	prime func(mock sqlmock.Sqlmock, n int64)
	call  func(r *classRepos) (int64, error)
}

func bulkSweepAxes() []bulkSweepAxis {
	exec := func(pattern string) func(sqlmock.Sqlmock, int64) {
		return func(m sqlmock.Sqlmock, n int64) {
			m.ExpectExec(pattern).WillReturnResult(sqlmock.NewResult(0, n))
		}
	}
	return []bulkSweepAxis{
		{
			name:  "APIKeyRepository.DeleteExpiredKeys",
			prime: exec("DELETE FROM api_keys"),
			call:  func(r *classRepos) (int64, error) { return r.keys.DeleteExpiredKeys(context.Background()) },
		},
		{
			// Since v0.25.0 this sweep RETURNs the organization ids it removed
			// rather than a bare count (see issues #160/#162), so it is primed as
			// a query. The class invariant under test is unchanged: a bulk sweep
			// that touched nothing reports emptiness IN BAND and must not report
			// ErrNotFound.
			name: "OrganizationRepository.RemoveAllMembershipsForUser",
			prime: func(m sqlmock.Sqlmock, n int64) {
				rows := sqlmock.NewRows([]string{"organization_id"})
				for i := int64(0); i < n; i++ {
					rows.AddRow(fmt.Sprintf("org-%d", i))
				}
				m.ExpectQuery("DELETE FROM organization_members").WillReturnRows(rows)
			},
			call: func(r *classRepos) (int64, error) {
				removed, err := r.orgs.RemoveAllMembershipsForUser(context.Background(), "user-1", OrgScopeAllOrganizations())
				return int64(len(removed.OrganizationIDs())), err
			},
		},
		{
			name:  "APIKeyRepository.RevokeAPIKeysForUser",
			prime: exec("DELETE FROM api_keys WHERE user_id"),
			call: func(r *classRepos) (int64, error) {
				return r.keys.RevokeAPIKeysForUser(context.Background(), "user-1", OrgScopeAllOrganizations())
			},
		},
		{
			name:  "OIDCConfigRepository.DeactivateAllOIDCConfigs",
			prime: exec("UPDATE oidc_config SET is_active = false"),
			call:  func(r *classRepos) (int64, error) { return r.oidc.DeactivateAllOIDCConfigs(context.Background()) },
		},
		{
			name:  "TokenRepository.CleanupExpiredRevocations",
			prime: exec("DELETE FROM revoked_tokens"),
			call:  func(r *classRepos) (int64, error) { return r.tokens.CleanupExpiredRevocations(context.Background()) },
		},
		{
			// Already returned its count before this batch; included so the bulk
			// convention is pinned as a whole rather than per-method.
			name:  "AuditRepository.DeleteAuditLogsBefore",
			prime: exec("DELETE FROM audit_logs"),
			call: func(r *classRepos) (int64, error) {
				return r.audit.DeleteAuditLogsBefore(context.Background(), time.Now(), 100)
			},
		},
	}
}

// TestNotFoundClass_BulkSweepReportsCountNotSentinel pins the deliberate
// asymmetry: for a sweep, zero rows is a correct answer and must NOT be an
// error — but it must still be reported, as a count.
func TestNotFoundClass_BulkSweepReportsCountNotSentinel(t *testing.T) {
	for _, axis := range bulkSweepAxes() {
		for _, want := range []int64{0, 7} {
			t.Run(axis.name, func(t *testing.T) {
				repos, mock := newClassRepos(t)
				axis.prime(mock, want)

				got, err := axis.call(repos)
				if err != nil {
					t.Fatalf("%s: sweeping %d rows returned err=%v; a bulk zero is not a miss",
						axis.name, want, err)
				}
				if got != want {
					t.Errorf("%s: reported %d rows, want %d", axis.name, got, want)
				}
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Errorf("%s: %v", axis.name, err)
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// The deliberate absorbers
// ---------------------------------------------------------------------------

// TestNotFoundClass_AbsorbersStayInBand pins the two accessors that must NOT
// propagate ErrNotFound because they already carry "nothing matched" in their
// own return values — and, in the same table, that a REAL failure still
// propagates from both. Absorbing every error would be a fail-open: a database
// fault would read as "not a member" / "no scopes".
func TestNotFoundClass_AbsorbersStayInBand(t *testing.T) {
	t.Run("CheckMembership reports non-membership as false, nil", func(t *testing.T) {
		repos, mock := newClassRepos(t)
		mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
			WillReturnRows(emptyOrgMemberRow())

		ok, role, err := repos.orgs.CheckMembership(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations())
		if err != nil {
			t.Fatalf("err = %v, want nil (the boolean already says 'not a member')", err)
		}
		if ok || role != nil {
			t.Errorf("got (%v, %v), want (false, nil)", ok, role)
		}
	})

	t.Run("CheckMembership propagates a real failure", func(t *testing.T) {
		repos, mock := newClassRepos(t)
		mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
			WillReturnError(errDB)

		ok, _, err := repos.orgs.CheckMembership(context.Background(), "org-1", "user-1", OrgScopeAllOrganizations())
		if err == nil {
			t.Fatal("a failed lookup returned nil error; 'could not tell' must not read as 'not a member'")
		}
		if ok {
			t.Error("a failed lookup reported membership")
		}
	})

	t.Run("GetUserScopesForOrg reports non-membership as an empty set", func(t *testing.T) {
		repos, mock := newClassRepos(t)
		mock.ExpectQuery("FROM organization_members").
			WillReturnRows(sqlmock.NewRows(orgMemberWithRoleRepoCols))

		scopes, err := repos.orgs.GetUserScopesForOrg(context.Background(), "user-1", "org-1")
		if err != nil {
			t.Fatalf("err = %v, want nil (an empty scope set already denies everything)", err)
		}
		if scopes == nil || len(scopes) != 0 {
			t.Errorf("scopes = %v, want an empty non-nil slice", scopes)
		}
	})

	t.Run("GetUserScopesForOrg propagates a real failure", func(t *testing.T) {
		repos, mock := newClassRepos(t)
		mock.ExpectQuery("FROM organization_members").WillReturnError(errDB)

		scopes, err := repos.orgs.GetUserScopesForOrg(context.Background(), "user-1", "org-1")
		if err == nil {
			t.Fatal("a failed lookup returned nil error; a database fault must not read as 'no permissions'")
		}
		if scopes != nil {
			t.Errorf("scopes = %v, want nil on error", scopes)
		}
	})
}

// TestNotFoundClass_DefaultOrgMissIsNotCached pins that the cached accessor does
// not memoize a miss. Caching one would pin a misconfiguration in place for a
// further TTL after it had been corrected.
func TestNotFoundClass_DefaultOrgMissIsNotCached(t *testing.T) {
	repos, mock := newClassRepos(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").WillReturnRows(emptyOrgRow())
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").WillReturnRows(sampleOrgRow())

	if _, err := repos.orgs.GetDefaultOrganization(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("first call: err = %v, want ErrNotFound", err)
	}
	org, err := repos.orgs.GetDefaultOrganization(context.Background())
	if err != nil {
		t.Fatalf("second call: err = %v, want nil — the miss was cached", err)
	}
	if org == nil {
		t.Fatal("second call returned a nil organization with a nil error")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// ---------------------------------------------------------------------------
// Structural guards — the substitute for a compile error
// ---------------------------------------------------------------------------

// storePackageFiles parses every non-test .go file in this package.
func storePackageFiles(t *testing.T) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	pkg, ok := pkgs["store"]
	if !ok {
		t.Fatal("package store not found")
	}
	return fset, pkg.Files
}

// TestNotFoundClass_NoAccessorReturnsNilNil is the first structural guard: the
// literal `return nil, nil` must not reappear anywhere in the package.
//
// This exists because the class has no compile forcing function. A new accessor
// written in the old style compiles, passes every existing test, and silently
// hands its caller a nil-dereference trap; nothing but this assertion notices.
func TestNotFoundClass_NoAccessorReturnsNilNil(t *testing.T) {
	fset, files := storePackageFiles(t)
	for name, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			ret, ok := n.(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 2 {
				return true
			}
			for _, r := range ret.Results {
				id, ok := r.(*ast.Ident)
				if !ok || id.Name != "nil" {
					return true
				}
			}
			t.Errorf("%s: `return nil, nil` at %s reintroduces the not-found trap this "+
				"package removed in v0.24.0; return an error wrapping ErrNotFound instead "+
				"(see errors.go for the two accessors allowed to absorb it, and why)",
				name, fset.Position(ret.Pos()))
			return true
		})
	}
}

// execDiscarders returns the name of every function in the package that calls
// ExecContext and throws the sql.Result away.
func execDiscarders(t *testing.T) []string {
	t.Helper()
	_, files := storePackageFiles(t)
	found := map[string]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok {
				return true
			}
			ast.Inspect(fn.Body, func(inner ast.Node) bool {
				assign, ok := inner.(*ast.AssignStmt)
				if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
					return true
				}
				id, ok := assign.Lhs[0].(*ast.Ident)
				if !ok || id.Name != "_" {
					return true
				}
				call, ok := assign.Rhs[0].(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "ExecContext" {
					return true
				}
				found[fn.Name.Name] = true
				return true
			})
			return false
		})
	}
	out := make([]string, 0, len(found))
	for k := range found {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestNotFoundClass_ExecResultDiscardersAreEnumerated is the second structural
// guard: every mutation that throws away its sql.Result — and so cannot tell a
// zero-row statement from a successful one — must be on this list, with a reason.
//
// The list is exhaustive on purpose. A new by-identifier UPDATE or DELETE that
// forgets requireRow fails here with the name of the offending function, which
// is the compile error this batch does not otherwise get.
func TestNotFoundClass_ExecResultDiscardersAreEnumerated(t *testing.T) {
	// Each entry is an INSERT (a zero-row insert is impossible without an
	// ON CONFLICT clause, and the two that have one treat zero rows as an
	// idempotent success), or a bulk statement whose caller does not act on the
	// count.
	//
	// CreateAPIKey and AddMemberWithRoleTemplate LEFT this list in v0.25.0. Both
	// gained a required OrgScope, and both apply it by sourcing the INSERT from a
	// scoped SELECT over the organizations table, so a zero-row insert became
	// possible for the first time — it is what an out-of-scope (or absent) target
	// organization produces — and both now route through requireRow. That is the
	// list doing its job in the direction it was written for: a mutation whose
	// zero-row case becomes reachable must stop discarding its result.
	allowed := map[string]string{
		"CreateUser":                 "plain INSERT; a unique violation surfaces as an error, so zero rows cannot happen",
		"CreateRoleTemplate":         "plain INSERT",
		"CreateOIDCConfig":           "plain INSERT (both the plain and transactional paths)",
		"RevokeToken":                "INSERT ... ON CONFLICT DO NOTHING; zero rows means already revoked, an idempotent success",
		"deactivateAllOIDCConfigsTx": "bulk UPDATE inside a transaction; zero rows means there were no configs",
		"maybePruneExpiredRevocations": "best-effort bounded prune; it must never fail the revocation " +
			"that triggered it, so it deliberately acts on nothing but the error",
	}

	got := execDiscarders(t)
	for _, name := range got {
		if _, ok := allowed[name]; !ok {
			t.Errorf("%s discards its ExecContext result, so a statement matching zero rows is "+
				"indistinguishable from one that did the work. Route it through requireRow "+
				"(by-identifier) or affectedRows (bulk); if it is genuinely an insert, add it to "+
				"this test's allowlist with the reason.", name)
		}
	}
	for name := range allowed {
		found := false
		for _, g := range got {
			if g == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s is allowlisted as discarding its ExecContext result but no longer does; "+
				"remove the stale entry so the list keeps meaning what it says", name)
		}
	}
}
