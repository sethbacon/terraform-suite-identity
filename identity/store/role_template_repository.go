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

// ListRoleTemplates returns all role templates.
func (r *RoleTemplateRepository) ListRoleTemplates(ctx context.Context) ([]*models.RoleTemplate, error) {
	query := `SELECT id, name, display_name, description, scopes, is_system, created_at, updated_at
			  FROM role_templates ORDER BY name`

	rows, err := r.db.QueryxContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []*models.RoleTemplate
	for rows.Next() {
		var t models.RoleTemplate
		var scopesJSON []byte
		if err := rows.Scan(&t.ID, &t.Name, &t.DisplayName, &t.Description, &scopesJSON, &t.IsSystem, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(scopesJSON, &t.Scopes); err != nil {
			return nil, err
		}
		templates = append(templates, &t)
	}

	return templates, rows.Err()
}

// GetRoleTemplate retrieves a role template by ID.
func (r *RoleTemplateRepository) GetRoleTemplate(ctx context.Context, id uuid.UUID) (*models.RoleTemplate, error) {
	query := `SELECT id, name, display_name, description, scopes, is_system, created_at, updated_at
			  FROM role_templates WHERE id = $1`

	var t models.RoleTemplate
	var scopesJSON []byte
	err := r.db.QueryRowxContext(ctx, query, id).Scan(&t.ID, &t.Name, &t.DisplayName, &t.Description, &scopesJSON, &t.IsSystem, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(scopesJSON, &t.Scopes); err != nil {
		return nil, err
	}

	return &t, nil
}

// GetRoleTemplateByName retrieves a role template by name.
func (r *RoleTemplateRepository) GetRoleTemplateByName(ctx context.Context, name string) (*models.RoleTemplate, error) {
	query := `SELECT id, name, display_name, description, scopes, is_system, created_at, updated_at
			  FROM role_templates WHERE name = $1`

	var t models.RoleTemplate
	var scopesJSON []byte
	err := r.db.QueryRowxContext(ctx, query, name).Scan(&t.ID, &t.Name, &t.DisplayName, &t.Description, &scopesJSON, &t.IsSystem, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(scopesJSON, &t.Scopes); err != nil {
		return nil, err
	}

	return &t, nil
}

// CreateRoleTemplate creates a new role template.
func (r *RoleTemplateRepository) CreateRoleTemplate(ctx context.Context, template *models.RoleTemplate) error {
	scopesJSON, err := json.Marshal(template.Scopes)
	if err != nil {
		return err
	}

	query := `INSERT INTO role_templates (id, name, display_name, description, scopes, is_system, created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err = r.db.ExecContext(ctx, query,
		template.ID, template.Name, template.DisplayName, template.Description, scopesJSON, template.IsSystem, template.CreatedAt, template.UpdatedAt)
	return err
}

// UpdateRoleTemplate updates an existing role template (non-system only).
func (r *RoleTemplateRepository) UpdateRoleTemplate(ctx context.Context, template *models.RoleTemplate) error {
	scopesJSON, err := json.Marshal(template.Scopes)
	if err != nil {
		return err
	}

	query := `UPDATE role_templates SET display_name = $2, description = $3, scopes = $4, updated_at = $5
			  WHERE id = $1 AND is_system = false`

	result, err := r.db.ExecContext(ctx, query,
		template.ID, template.DisplayName, template.Description, scopesJSON, time.Now())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
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
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("role template %s not found or is a system template (immutable)", id)
	}
	return nil
}
