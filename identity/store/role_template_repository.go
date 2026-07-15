// role_template_repository.go implements RoleTemplateRepository: CRUD for the
// identity role_templates table. Scope contents are app-defined (each app seeds
// its own role→scope mapping); this layer is app-agnostic.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
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

// NewRoleTemplateRepository creates a new RoleTemplateRepository.
func NewRoleTemplateRepository(db *sqlx.DB) *RoleTemplateRepository {
	return &RoleTemplateRepository{db: db}
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
func (r *RoleTemplateRepository) GetRoleTemplate(ctx context.Context, id uuid.UUID) (*models.RoleTemplate, error) {
	query := `SELECT id, name, display_name, description, scopes, is_system, created_at, updated_at
			  FROM role_templates WHERE id = $1`

	var row roleTemplateRow
	err := r.db.QueryRowxContext(ctx, query, id).StructScan(&row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role template: %w", err)
	}

	return row.toModel()
}

// GetRoleTemplateByName retrieves a role template by name.
func (r *RoleTemplateRepository) GetRoleTemplateByName(ctx context.Context, name string) (*models.RoleTemplate, error) {
	query := `SELECT id, name, display_name, description, scopes, is_system, created_at, updated_at
			  FROM role_templates WHERE name = $1`

	var row roleTemplateRow
	err := r.db.QueryRowxContext(ctx, query, name).StructScan(&row)
	if err == sql.ErrNoRows {
		return nil, nil
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

// UpdateRoleTemplate updates an existing role template (non-system only).
func (r *RoleTemplateRepository) UpdateRoleTemplate(ctx context.Context, template *models.RoleTemplate) error {
	scopesJSON, err := json.Marshal(template.Scopes)
	if err != nil {
		return fmt.Errorf("failed to marshal role template scopes: %w", err)
	}

	query := `UPDATE role_templates SET display_name = $2, description = $3, scopes = $4, updated_at = $5
			  WHERE id = $1 AND is_system = false`

	result, err := r.db.ExecContext(ctx, query,
		template.ID, template.DisplayName, template.Description, scopesJSON, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update role template: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected updating role template: %w", err)
	}
	if n == 0 {
		// The WHERE also matches on is_system = false, so zero rows means the
		// template does not exist or is a system template. Surface it instead of
		// reporting a silent success.
		return fmt.Errorf("role template %s not found or is a system template (immutable)", template.ID)
	}
	return nil
}

// DeleteRoleTemplate deletes a role template (non-system only).
func (r *RoleTemplateRepository) DeleteRoleTemplate(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM role_templates WHERE id = $1 AND is_system = false`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete role template: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected deleting role template: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("role template %s not found or is a system template (immutable)", id)
	}
	return nil
}

// Create is an alias for CreateRoleTemplate to match admin handlers, mirroring
// the short-name alias convention already used by UserRepository,
// APIKeyRepository, and OrganizationRepository. Added so a consumer can call
// RoleTemplateRepository directly with the same naming convention instead of
// needing its own wrapper type.
func (r *RoleTemplateRepository) Create(ctx context.Context, template *models.RoleTemplate) error {
	return r.CreateRoleTemplate(ctx, template)
}

// GetByID is an alias for GetRoleTemplate to match admin handlers.
func (r *RoleTemplateRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.RoleTemplate, error) {
	return r.GetRoleTemplate(ctx, id)
}

// Update is an alias for UpdateRoleTemplate to match admin handlers.
func (r *RoleTemplateRepository) Update(ctx context.Context, template *models.RoleTemplate) error {
	return r.UpdateRoleTemplate(ctx, template)
}

// Delete is an alias for DeleteRoleTemplate to match admin handlers.
func (r *RoleTemplateRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.DeleteRoleTemplate(ctx, id)
}

// List is an alias for ListRoleTemplates to match admin handlers.
func (r *RoleTemplateRepository) List(ctx context.Context) ([]*models.RoleTemplate, error) {
	return r.ListRoleTemplates(ctx)
}
