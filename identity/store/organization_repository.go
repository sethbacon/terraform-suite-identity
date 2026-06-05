package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// OrganizationRepository is the data-access layer for organizations and their members.
type OrganizationRepository struct {
	db *sql.DB
}

// NewOrganizationRepository constructs an OrganizationRepository over the given connection.
func NewOrganizationRepository(db *sql.DB) *OrganizationRepository {
	return &OrganizationRepository{db: db}
}

func (r *OrganizationRepository) GetOrganizationByID(ctx context.Context, id string) (*models.Organization, error) {
	var org models.Organization
	err := r.db.QueryRowContext(ctx,
		"SELECT id, name, display_name, description, is_active, created_at, updated_at FROM organizations WHERE id = $1", id,
	).Scan(&org.ID, &org.Name, &org.DisplayName, &org.Description, &org.IsActive, &org.CreatedAt, &org.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}
	return &org, nil
}

func (r *OrganizationRepository) GetOrganizationByName(ctx context.Context, name string) (*models.Organization, error) {
	var org models.Organization
	err := r.db.QueryRowContext(ctx,
		"SELECT id, name, display_name, description, is_active, created_at, updated_at FROM organizations WHERE name = $1", name,
	).Scan(&org.ID, &org.Name, &org.DisplayName, &org.Description, &org.IsActive, &org.CreatedAt, &org.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get organization by name: %w", err)
	}
	return &org, nil
}

func (r *OrganizationRepository) CreateOrganization(ctx context.Context, org *models.Organization) error {
	err := r.db.QueryRowContext(ctx,
		`INSERT INTO organizations (name, display_name, description, is_active) VALUES ($1, $2, $3, $4) RETURNING id, created_at, updated_at`,
		org.Name, org.DisplayName, org.Description, org.IsActive,
	).Scan(&org.ID, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create organization: %w", err)
	}
	return nil
}

func (r *OrganizationRepository) UpdateOrganization(ctx context.Context, org *models.Organization) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE organizations SET name = $1, display_name = $2, description = $3, is_active = $4, updated_at = $5 WHERE id = $6`,
		org.Name, org.DisplayName, org.Description, org.IsActive, time.Now(), org.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update organization: %w", err)
	}
	return nil
}

func (r *OrganizationRepository) DeleteOrganization(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM organizations WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete organization: %w", err)
	}
	return nil
}

func (r *OrganizationRepository) ListOrganizations(ctx context.Context, offset, limit int) ([]*models.Organization, int, error) {
	var total int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM organizations").Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count organizations: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		"SELECT id, name, display_name, description, is_active, created_at, updated_at FROM organizations ORDER BY name LIMIT $1 OFFSET $2",
		limit, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var orgs []*models.Organization
	for rows.Next() {
		var o models.Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.DisplayName, &o.Description, &o.IsActive, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("failed to scan organization: %w", err)
		}
		orgs = append(orgs, &o)
	}
	return orgs, total, nil
}

func (r *OrganizationRepository) SearchOrganizations(ctx context.Context, query string, limit int) ([]*models.Organization, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, display_name, description, is_active, created_at, updated_at
         FROM organizations WHERE name ILIKE $1 OR display_name ILIKE $1 ORDER BY name LIMIT $2`,
		"%"+query+"%", limit,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to search organizations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var orgs []*models.Organization
	for rows.Next() {
		var o models.Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.DisplayName, &o.Description, &o.IsActive, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan organization: %w", err)
		}
		orgs = append(orgs, &o)
	}
	return orgs, nil
}

func (r *OrganizationRepository) AddMember(ctx context.Context, member *models.OrganizationMember) error {
	err := r.db.QueryRowContext(ctx,
		`INSERT INTO organization_members (organization_id, user_id, role_template_id) VALUES ($1, $2, $3) RETURNING id, created_at, updated_at`,
		member.OrganizationID, member.UserID, member.RoleTemplateID,
	).Scan(&member.ID, &member.CreatedAt, &member.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}
	return nil
}

func (r *OrganizationRepository) GetMember(ctx context.Context, orgID, userID string) (*models.OrganizationMember, error) {
	var m models.OrganizationMember
	err := r.db.QueryRowContext(ctx,
		"SELECT id, organization_id, user_id, role_template_id, created_at, updated_at FROM organization_members WHERE organization_id = $1 AND user_id = $2",
		orgID, userID,
	).Scan(&m.ID, &m.OrganizationID, &m.UserID, &m.RoleTemplateID, &m.CreatedAt, &m.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get member: %w", err)
	}
	return &m, nil
}

func (r *OrganizationRepository) GetMemberWithRole(ctx context.Context, orgID, userID string) (*models.OrganizationMemberWithRole, error) {
	var m models.OrganizationMemberWithRole
	var scopes []string
	err := r.db.QueryRowContext(ctx,
		`SELECT om.id, om.organization_id, om.user_id, om.role_template_id, om.created_at, om.updated_at,
                u.email as user_email, u.name as user_name,
                rt.name as role_template_name, COALESCE(rt.scopes, '{}') as scopes
         FROM organization_members om
         JOIN users u ON om.user_id = u.id
         LEFT JOIN role_templates rt ON om.role_template_id = rt.id
         WHERE om.organization_id = $1 AND om.user_id = $2`,
		orgID, userID,
	).Scan(&m.ID, &m.OrganizationID, &m.UserID, &m.RoleTemplateID, &m.CreatedAt, &m.UpdatedAt,
		&m.UserEmail, &m.UserName, &m.RoleTemplateName, pq.Array(&scopes))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get member with role: %w", err)
	}
	m.RoleTemplateScopes = scopes
	return &m, nil
}

func (r *OrganizationRepository) ListMembers(ctx context.Context, orgID string) ([]*models.OrganizationMemberWithRole, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT om.id, om.organization_id, om.user_id, om.role_template_id, om.created_at, om.updated_at,
                u.email as user_email, u.name as user_name,
                rt.name as role_template_name, COALESCE(rt.scopes, '{}') as scopes
         FROM organization_members om
         JOIN users u ON om.user_id = u.id
         LEFT JOIN role_templates rt ON om.role_template_id = rt.id
         WHERE om.organization_id = $1
         ORDER BY u.name`,
		orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list members: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var members []*models.OrganizationMemberWithRole
	for rows.Next() {
		var m models.OrganizationMemberWithRole
		var scopes []string
		if err := rows.Scan(&m.ID, &m.OrganizationID, &m.UserID, &m.RoleTemplateID, &m.CreatedAt, &m.UpdatedAt,
			&m.UserEmail, &m.UserName, &m.RoleTemplateName, pq.Array(&scopes)); err != nil {
			return nil, fmt.Errorf("failed to scan member: %w", err)
		}
		m.RoleTemplateScopes = scopes
		members = append(members, &m)
	}
	return members, nil
}

func (r *OrganizationRepository) UpdateMember(ctx context.Context, orgID, userID string, roleTemplateID *string) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE organization_members SET role_template_id = $1, updated_at = $2 WHERE organization_id = $3 AND user_id = $4",
		roleTemplateID, time.Now(), orgID, userID,
	)
	if err != nil {
		return fmt.Errorf("failed to update member: %w", err)
	}
	return nil
}

func (r *OrganizationRepository) RemoveMember(ctx context.Context, orgID, userID string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2", orgID, userID)
	if err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}
	return nil
}
