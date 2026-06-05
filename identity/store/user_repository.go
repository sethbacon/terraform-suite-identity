// Package store provides the identity data-access layer (repositories) over the
// shared identity tables. Repositories take a standard *sql.DB (or *sqlx.DB) and
// use unqualified table names, so the active schema is determined by the
// connection's search_path — letting a caller target either the public or the
// dedicated identity schema without query changes.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// UserRepository is the data-access layer for identity users.
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository constructs a UserRepository over the given connection.
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	var user models.User
	err := r.db.QueryRowContext(ctx,
		"SELECT id, email, name, oidc_sub, is_active, created_at, updated_at FROM users WHERE id = $1",
		id,
	).Scan(&user.ID, &user.Email, &user.Name, &user.OIDCSub, &user.IsActive, &user.CreatedAt, &user.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}
	return &user, nil
}

func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := r.db.QueryRowContext(ctx,
		"SELECT id, email, name, oidc_sub, is_active, created_at, updated_at FROM users WHERE email = $1",
		email,
	).Scan(&user.ID, &user.Email, &user.Name, &user.OIDCSub, &user.IsActive, &user.CreatedAt, &user.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	return &user, nil
}

func (r *UserRepository) GetUserByOIDCSub(ctx context.Context, sub string) (*models.User, error) {
	var user models.User
	err := r.db.QueryRowContext(ctx,
		"SELECT id, email, name, oidc_sub, is_active, created_at, updated_at FROM users WHERE oidc_sub = $1",
		sub,
	).Scan(&user.ID, &user.Email, &user.Name, &user.OIDCSub, &user.IsActive, &user.CreatedAt, &user.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by OIDC sub: %w", err)
	}
	return &user, nil
}

func (r *UserRepository) CreateUser(ctx context.Context, user *models.User) error {
	err := r.db.QueryRowContext(ctx,
		`INSERT INTO users (email, name, oidc_sub, is_active)
         VALUES ($1, $2, $3, $4)
         RETURNING id, created_at, updated_at`,
		user.Email, user.Name, user.OIDCSub, user.IsActive,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

func (r *UserRepository) UpdateUser(ctx context.Context, user *models.User) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET email = $1, name = $2, oidc_sub = $3, is_active = $4, updated_at = $5 WHERE id = $6`,
		user.Email, user.Name, user.OIDCSub, user.IsActive, time.Now(), user.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return nil
}

func (r *UserRepository) DeleteUser(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM users WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

func (r *UserRepository) ListUsers(ctx context.Context, offset, limit int) ([]*models.User, int, error) {
	var total int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		"SELECT id, email, name, oidc_sub, is_active, created_at, updated_at FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2",
		limit, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []*models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.OIDCSub, &u.IsActive, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, &u)
	}
	return users, total, nil
}

func (r *UserRepository) SearchUsers(ctx context.Context, query string, limit int) ([]*models.User, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, email, name, oidc_sub, is_active, created_at, updated_at
         FROM users WHERE email ILIKE $1 OR name ILIKE $1 ORDER BY name LIMIT $2`,
		"%"+query+"%", limit,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to search users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []*models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.OIDCSub, &u.IsActive, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, &u)
	}
	return users, nil
}

// GetUserWithOrgRoles gets a user with their organization memberships and scopes.
func (r *UserRepository) GetUserWithOrgRoles(ctx context.Context, userID string) (*models.UserWithOrgRoles, error) {
	var u models.UserWithOrgRoles
	var scopes []string
	err := r.db.QueryRowContext(ctx,
		`SELECT u.id, u.email, u.name, u.oidc_sub, u.is_active, u.created_at, u.updated_at,
                om.organization_id, o.name as organization_name, rt.name as role_template_name,
                COALESCE(rt.scopes, '{}') as scopes
         FROM users u
         LEFT JOIN organization_members om ON u.id = om.user_id
         LEFT JOIN organizations o ON om.organization_id = o.id
         LEFT JOIN role_templates rt ON om.role_template_id = rt.id
         WHERE u.id = $1
         LIMIT 1`,
		userID,
	).Scan(&u.ID, &u.Email, &u.Name, &u.OIDCSub, &u.IsActive, &u.CreatedAt, &u.UpdatedAt,
		&u.OrganizationID, &u.OrganizationName, &u.RoleTemplateName, pq.Array(&scopes))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user with org roles: %w", err)
	}
	u.Scopes = scopes
	return &u, nil
}
