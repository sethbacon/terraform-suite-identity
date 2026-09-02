// role_template_repository.go implements RoleTemplateRepository: CRUD for the
// identity role_templates table. Scope contents are app-defined (each app seeds
// its own role→scope mapping); this layer is app-agnostic.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// RoleTemplateRepository handles database operations for role templates.
type RoleTemplateRepository struct {
	db *sqlx.DB
}

// NewRoleTemplateRepository creates a new RoleTemplateRepository over the same
// *sql.DB every other repository in this package takes.
//
// sqlx is an implementation detail here, not part of the contract: the read
// methods use StructScan against the db-tagged roleTemplateRow, so the
// dependency earns its keep internally, but it is wrapped with sqlx.NewDb —
// which adorns an existing pool rather than opening a second one — instead of
// being pushed onto the caller. Until v0.25.0 this constructor and
// NewOIDCConfigRepository were the only two in the package that demanded a
// *sqlx.DB, which forced every consuming application to construct and inject
// two handle types for one identity layer; terraform-state-manager-backend was
// literally writing sqlx.NewDb(identityDB, "postgres") at the call site to
// satisfy it. That wrapping now happens once, here.
func NewRoleTemplateRepository(db *sql.DB) *RoleTemplateRepository {
	return &RoleTemplateRepository{db: newSqlxDB(db)}
}

// roleTemplateRow is the sqlx StructScan target for a role_templates row.
// scopes is scanned into a raw JSONB byte slice (rather than models.RoleTemplate's
// []string Scopes field directly) since sqlx has no built-in JSONB-to-[]string
// conversion; toModel does that unmarshal explicitly.
type roleTemplateRow struct {
	ID          uuid.UUID `db:"id"`
	Name        string    `db:"name"`
	DisplayName string    `db:"display_name"`
	Description *string   `db:"description"`
	ScopesJSON  []byte    `db:"scopes"`
	IsSystem    bool      `db:"is_system"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

func (row *roleTemplateRow) toModel() (*models.RoleTemplate, error) {
	var scopes []string
	if err := json.Unmarshal(row.ScopesJSON, &scopes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal role template scopes: %w", err)
	}
	return &models.RoleTemplate{
		ID:          row.ID,
		Name:        row.Name,
		DisplayName: row.DisplayName,
		Description: row.Description,
		Scopes:      scopes,
		IsSystem:    row.IsSystem,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}, nil
}

// ListRoleTemplates returns all role templates.
func (r *RoleTemplateRepository) ListRoleTemplates(ctx context.Context) ([]*models.RoleTemplate, error) {
	query := `SELECT id, name, display_name, description, scopes, is_system, created_at, updated_at
			  FROM role_templates ORDER BY name`

	rows, err := r.db.QueryxContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list role templates: %w", err)
	}
	defer rows.Close()

	var templates []*models.RoleTemplate
	for rows.Next() {
		var row roleTemplateRow
		if err := rows.StructScan(&row); err != nil {
			return nil, fmt.Errorf("failed to scan role template: %w", err)
		}
		t, err := row.toModel()
		if err != nil {
			return nil, err
		}
		templates = append(templates, t)
	}

	return templates, rows.Err()
}

// GetRoleTemplate retrieves a role template by ID.
//
// Returns an error wrapping ErrNotFound when no template has that ID.
func (r *RoleTemplateRepository) GetRoleTemplate(ctx context.Context, id uuid.UUID) (*models.RoleTemplate, error) {
	query := `SELECT id, name, display_name, description, scopes, is_system, created_at, updated_at
			  FROM role_templates WHERE id = $1`

	var row roleTemplateRow
	err := r.db.QueryRowxContext(ctx, query, id).StructScan(&row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound("role template by id")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role template: %w", err)
	}

	return row.toModel()
}

// GetRoleTemplateByName retrieves a role template by name.
//
// Returns an error wrapping ErrNotFound when no template has that name.
func (r *RoleTemplateRepository) GetRoleTemplateByName(ctx context.Context, name string) (*models.RoleTemplate, error) {
	query := `SELECT id, name, display_name, description, scopes, is_system, created_at, updated_at
			  FROM role_templates WHERE name = $1`

	var row roleTemplateRow
	err := r.db.QueryRowxContext(ctx, query, name).StructScan(&row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound("role template by name")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role template by name: %w", err)
	}

	return row.toModel()
}

// CreateRoleTemplate creates a new role template.
func (r *RoleTemplateRepository) CreateRoleTemplate(ctx context.Context, template *models.RoleTemplate) error {
	scopesJSON, err := json.Marshal(template.Scopes)
	if err != nil {
		return fmt.Errorf("failed to marshal role template scopes: %w", err)
	}

	query := `INSERT INTO role_templates (id, name, display_name, description, scopes, is_system, created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err = r.db.ExecContext(ctx, query,
		template.ID, template.Name, template.DisplayName, template.Description, scopesJSON, template.IsSystem, template.CreatedAt, template.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create role template: %w", err)
	}
	return nil
}

// updateRoleTemplateStmt and deleteRoleTemplateStmt are the two statements that
// can reduce authority for every membership holding a template (issue #282).
//
// They are package constants with exactly one copy each because TWO callers
// issue them: the plain repository methods below, and TemplateWriter in
// template_write.go, which runs the credential reconciliation first and then
// this same statement. A second hand-written copy in the writer would be a
// statement that can drift from the one the repository's own tests and the
// authority-reduction inventory are written against — and the WHERE clause here
// carries the is_system immutability rule, which is not a detail worth having
// two versions of.
//
// Being package constants is also what keeps both callers VISIBLE to the
// inventory scan in authority_reduction_class_test.go: it resolves a
// package-level string constant referenced by identifier inside a function
// body, so every function that names one of these is attributed the statement.
// A writer that delegated to the repository method instead would issue no SQL
// of its own and would therefore be invisible to that scan, which is precisely
// the "delegating wrappers" blind spot the guard documents about itself.
const (
	updateRoleTemplateStmt = `UPDATE role_templates SET display_name = $2, description = $3, scopes = $4, updated_at = $5
			  WHERE id = $1 AND is_system = false`

	deleteRoleTemplateStmt = `DELETE FROM role_templates WHERE id = $1 AND is_system = false`
)

// roleTemplateExecer is the subset of a database handle these two statements
// need. Both *sqlx.DB (the repository's handle) and *sql.DB (the writer's)
// satisfy it, so neither caller has to convert the other's handle type.
type roleTemplateExecer interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

// updateRoleTemplateArgs renders one template as updateRoleTemplateStmt's
// arguments, in its parameter order.
//
// Shared for the same reason the statement itself is: the argument list and the
// $N placeholders are one fact, and a caller that assembled its own could put
// the scopes where the description goes and still compile.
func updateRoleTemplateArgs(template *models.RoleTemplate) ([]interface{}, error) {
	scopesJSON, err := json.Marshal(template.Scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal role template scopes: %w", err)
	}
	return []interface{}{template.ID, template.DisplayName, template.Description, scopesJSON, time.Now()}, nil
}

// execRoleTemplateMutation runs one of the two statements above and applies the
// shared zero-row rule.
//
// The zero-row error WRAPS ErrNotFound, so one errors.Is check covers every
// accessor in the package rather than this one needing a string match. Because
// both statements also filter is_system, zero rows means "no such template, or
// it is a system template" — both are "matched no row", and the message says
// which possibilities apply rather than reporting a silent success.
func execRoleTemplateMutation(ctx context.Context, db roleTemplateExecer, stmt string, id uuid.UUID, args ...interface{}) error {
	result, err := db.ExecContext(ctx, stmt, args...)
	if err != nil {
		return fmt.Errorf("failed to mutate role template: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected mutating role template: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("role template %s not found or is a system template (immutable): %w", id, ErrNotFound)
	}
	return nil
}

// UpdateRoleTemplate updates an existing role template (non-system only).
//
// IT INVALIDATES NOTHING, and that is a choice this signature makes visible.
// Narrowing a template's scopes narrows what every membership holding it
// grants, while every API key those members hold keeps working from the scope
// snapshot frozen on it at creation. TemplateWriter.UpdateRoleTemplate
// (template_write.go) is the path that reconciles those credentials first and
// then issues this same statement; this one is for a caller who has decided,
// deliberately, that the reduction needs no sweep — an app that keeps its own
// per-app mirror and sweeps from that, or an edit known to widen. Choosing it
// is a different symbol rather than an omitted argument, exactly as choosing
// OrganizationRepository.RemoveMember over Reducer.RemoveMember is.
func (r *RoleTemplateRepository) UpdateRoleTemplate(ctx context.Context, template *models.RoleTemplate) error {
	args, err := updateRoleTemplateArgs(template)
	if err != nil {
		return err
	}
	return execRoleTemplateMutation(ctx, r.db, updateRoleTemplateStmt, template.ID, args...)
}

// DeleteRoleTemplate deletes a role template (non-system only).
//
// As with UpdateRoleTemplate it invalidates nothing, and the blast radius is
// larger: organization_members.role_template_id is ON DELETE SET NULL, so every
// member holding the template is left with no role template — read everywhere
// in this package as no scopes at all — while their API keys keep the scopes
// the template used to grant. TemplateWriter.DeleteRoleTemplate is the path
// that sweeps first; it must be, because after this statement commits there is
// no longer any row saying who held the template.
func (r *RoleTemplateRepository) DeleteRoleTemplate(ctx context.Context, id uuid.UUID) error {
	return execRoleTemplateMutation(ctx, r.db, deleteRoleTemplateStmt, id, id)
}
