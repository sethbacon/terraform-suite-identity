package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// APIKeyRepository is the data-access layer for API keys.
type APIKeyRepository struct {
	db *sql.DB
}

// NewAPIKeyRepository constructs an APIKeyRepository over the given connection.
func NewAPIKeyRepository(db *sql.DB) *APIKeyRepository {
	return &APIKeyRepository{db: db}
}

func (r *APIKeyRepository) GetAPIKeysByPrefix(ctx context.Context, prefix string) ([]*models.APIKey, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, user_id, organization_id, name, description, key_hash, key_prefix, scopes,
                expires_at, last_used_at, is_active, created_at, updated_at
         FROM api_keys WHERE key_prefix = $1 AND is_active = true`,
		prefix,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get API keys by prefix: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var keys []*models.APIKey
	for rows.Next() {
		var k models.APIKey
		var scopes []string
		if err := rows.Scan(&k.ID, &k.UserID, &k.OrganizationID, &k.Name, &k.Description,
			&k.KeyHash, &k.KeyPrefix, pq.Array(&scopes),
			&k.ExpiresAt, &k.LastUsedAt, &k.IsActive, &k.CreatedAt, &k.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan API key: %w", err)
		}
		k.Scopes = scopes
		keys = append(keys, &k)
	}
	return keys, nil
}

func (r *APIKeyRepository) UpdateLastUsed(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE api_keys SET last_used_at = $1 WHERE id = $2",
		time.Now(), id,
	)
	if err != nil {
		return fmt.Errorf("failed to update last used: %w", err)
	}
	return nil
}

func (r *APIKeyRepository) CreateAPIKey(ctx context.Context, key *models.APIKey) error {
	err := r.db.QueryRowContext(ctx,
		`INSERT INTO api_keys (user_id, organization_id, name, description, key_hash, key_prefix, scopes, expires_at, is_active)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING id, created_at, updated_at`,
		key.UserID, key.OrganizationID, key.Name, key.Description, key.KeyHash, key.KeyPrefix,
		pq.Array(key.Scopes), key.ExpiresAt, key.IsActive,
	).Scan(&key.ID, &key.CreatedAt, &key.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create API key: %w", err)
	}
	return nil
}

func (r *APIKeyRepository) GetAPIKeyByID(ctx context.Context, id string) (*models.APIKey, error) {
	var k models.APIKey
	var scopes []string
	err := r.db.QueryRowContext(ctx,
		`SELECT id, user_id, organization_id, name, description, key_hash, key_prefix, scopes,
                expires_at, last_used_at, is_active, created_at, updated_at
         FROM api_keys WHERE id = $1`,
		id,
	).Scan(&k.ID, &k.UserID, &k.OrganizationID, &k.Name, &k.Description,
		&k.KeyHash, &k.KeyPrefix, pq.Array(&scopes),
		&k.ExpiresAt, &k.LastUsedAt, &k.IsActive, &k.CreatedAt, &k.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}
	k.Scopes = scopes
	return &k, nil
}

func (r *APIKeyRepository) ListAPIKeys(ctx context.Context, userID string) ([]*models.APIKey, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, user_id, organization_id, name, description, key_hash, key_prefix, scopes,
                expires_at, last_used_at, is_active, created_at, updated_at
         FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list API keys: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var keys []*models.APIKey
	for rows.Next() {
		var k models.APIKey
		var scopes []string
		if err := rows.Scan(&k.ID, &k.UserID, &k.OrganizationID, &k.Name, &k.Description,
			&k.KeyHash, &k.KeyPrefix, pq.Array(&scopes),
			&k.ExpiresAt, &k.LastUsedAt, &k.IsActive, &k.CreatedAt, &k.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan API key: %w", err)
		}
		k.Scopes = scopes
		keys = append(keys, &k)
	}
	return keys, nil
}

func (r *APIKeyRepository) UpdateAPIKey(ctx context.Context, key *models.APIKey) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE api_keys SET name = $1, description = $2, scopes = $3, expires_at = $4, is_active = $5, updated_at = $6 WHERE id = $7`,
		key.Name, key.Description, pq.Array(key.Scopes), key.ExpiresAt, key.IsActive, time.Now(), key.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update API key: %w", err)
	}
	return nil
}

func (r *APIKeyRepository) DeleteAPIKey(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM api_keys WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete API key: %w", err)
	}
	return nil
}

func (r *APIKeyRepository) RotateAPIKey(ctx context.Context, id, newHash, newPrefix string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE api_keys SET key_hash = $1, key_prefix = $2, updated_at = $3 WHERE id = $4`,
		newHash, newPrefix, time.Now(), id,
	)
	if err != nil {
		return fmt.Errorf("failed to rotate API key: %w", err)
	}
	return nil
}
