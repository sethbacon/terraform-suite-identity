package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// RoleTemplateRepository is the data-access layer for role templates.
type RoleTemplateRepository struct {
	db *sql.DB
}

// NewRoleTemplateRepository constructs a RoleTemplateRepository over the given connection.
func NewRoleTemplateRepository(db *sql.DB) *RoleTemplateRepository {
	return &RoleTemplateRepository{db: db}
}

func (r *RoleTemplateRepository) ListRoleTemplates(ctx context.Context) ([]*models.RoleTemplate, error) {
	rows, err := r.db.QueryContext(ctx,
		"SELECT id, name, display_name, description, scopes, is_system, created_at, updated_at FROM role_templates ORDER BY name",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list role templates: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var templates []*models.RoleTemplate
	for rows.Next() {
		var t models.RoleTemplate
		var scopes []string
		if err := rows.Scan(&t.ID, &t.Name, &t.DisplayName, &t.Description, pq.Array(&scopes), &t.IsSystem, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan role template: %w", err)
		}
		t.Scopes = scopes
		templates = append(templates, &t)
	}
	return templates, nil
}

func (r *RoleTemplateRepository) GetRoleTemplateByID(ctx context.Context, id string) (*models.RoleTemplate, error) {
	var t models.RoleTemplate
	var scopes []string
	err := r.db.QueryRowContext(ctx,
		"SELECT id, name, display_name, description, scopes, is_system, created_at, updated_at FROM role_templates WHERE id = $1", id,
	).Scan(&t.ID, &t.Name, &t.DisplayName, &t.Description, pq.Array(&scopes), &t.IsSystem, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role template: %w", err)
	}
	t.Scopes = scopes
	return &t, nil
}

func (r *RoleTemplateRepository) GetRoleTemplateByName(ctx context.Context, name string) (*models.RoleTemplate, error) {
	var t models.RoleTemplate
	var scopes []string
	err := r.db.QueryRowContext(ctx,
		"SELECT id, name, display_name, description, scopes, is_system, created_at, updated_at FROM role_templates WHERE name = $1", name,
	).Scan(&t.ID, &t.Name, &t.DisplayName, &t.Description, pq.Array(&scopes), &t.IsSystem, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role template by name: %w", err)
	}
	t.Scopes = scopes
	return &t, nil
}

func (r *RoleTemplateRepository) CreateRoleTemplate(ctx context.Context, t *models.RoleTemplate) error {
	err := r.db.QueryRowContext(ctx,
		`INSERT INTO role_templates (name, display_name, description, scopes, is_system) VALUES ($1, $2, $3, $4, $5)
         RETURNING id, created_at, updated_at`,
		t.Name, t.DisplayName, t.Description, pq.Array(t.Scopes), t.IsSystem,
	).Scan(&t.ID, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create role template: %w", err)
	}
	return nil
}

func (r *RoleTemplateRepository) UpdateRoleTemplate(ctx context.Context, t *models.RoleTemplate) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE role_templates SET name = $1, display_name = $2, description = $3, scopes = $4, updated_at = $5 WHERE id = $6`,
		t.Name, t.DisplayName, t.Description, pq.Array(t.Scopes), time.Now(), t.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update role template: %w", err)
	}
	return nil
}

func (r *RoleTemplateRepository) DeleteRoleTemplate(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM role_templates WHERE id = $1 AND is_system = false", id)
	if err != nil {
		return fmt.Errorf("failed to delete role template: %w", err)
	}
	return nil
}
