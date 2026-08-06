// api_key_repository.go implements APIKeyRepository, providing database queries for API key
// lookup by prefix, creation, expiry management, and last-used timestamp updates.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// APIKeyRepository handles API key database operations
type APIKeyRepository struct {
	db *sql.DB
}

// NewAPIKeyRepository creates a new APIKeyRepository
func NewAPIKeyRepository(db *sql.DB) *APIKeyRepository {
	return &APIKeyRepository{db: db}
}

// rowScanner abstracts *sql.Row and *sql.Rows, both of which implement Scan,
// so a single-row lookup and a multi-row list can share one scan function.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

// scanAPIKey scans the standard 12-column api_keys projection (id, user_id,
// organization_id, name, description, key_hash, key_prefix, scopes,
// expires_at, last_used_at, expiry_notification_sent_at, created_at) shared by
// GetAPIKeyByHash, GetAPIKeyByID, and GetAPIKeysByPrefix, including the
// scopes JSONB unmarshal.
func scanAPIKey(row rowScanner) (*models.APIKey, error) {
	apiKey := &models.APIKey{}
	var scopesJSON []byte
	if err := row.Scan(
		&apiKey.ID,
		&apiKey.UserID,
		&apiKey.OrganizationID,
		&apiKey.Name,
		&apiKey.Description,
		&apiKey.KeyHash,
		&apiKey.KeyPrefix,
		&scopesJSON,
		&apiKey.ExpiresAt,
		&apiKey.LastUsedAt,
		&apiKey.ExpiryNotificationSentAt,
		&apiKey.CreatedAt,
	); err != nil {
		return nil, err // sql.ErrNoRows must reach callers unwrapped so `err == sql.ErrNoRows` checks keep working
	}
	if err := json.Unmarshal(scopesJSON, &apiKey.Scopes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal api key scopes: %w", err)
	}
	return apiKey, nil
}

// scanAPIKeyWithUserName scans the same projection as scanAPIKey plus a
// joined u.name column, shared by ListAPIKeysByUser and
// ListAPIKeysByOrganization.
func scanAPIKeyWithUserName(rows *sql.Rows) (*models.APIKey, error) {
	apiKey := &models.APIKey{}
	var scopesJSON []byte
	if err := rows.Scan(
		&apiKey.ID,
		&apiKey.UserID,
		&apiKey.OrganizationID,
		&apiKey.Name,
		&apiKey.Description,
		&apiKey.KeyHash,
		&apiKey.KeyPrefix,
		&scopesJSON,
		&apiKey.ExpiresAt,
		&apiKey.LastUsedAt,
		&apiKey.ExpiryNotificationSentAt,
		&apiKey.CreatedAt,
		&apiKey.UserName,
	); err != nil {
		return nil, fmt.Errorf("failed to scan api key: %w", err)
	}
	if err := json.Unmarshal(scopesJSON, &apiKey.Scopes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal api key scopes: %w", err)
	}
	return apiKey, nil
}

// CreateAPIKey creates a new API key
func (r *APIKeyRepository) CreateAPIKey(ctx context.Context, apiKey *models.APIKey) error {
	apiKey.ID = uuid.New().String()
	apiKey.CreatedAt = time.Now()

	// Marshal scopes to JSONB
	scopesJSON, err := json.Marshal(apiKey.Scopes)
	if err != nil {
		return fmt.Errorf("failed to marshal api key scopes: %w", err)
	}

	query := `
		INSERT INTO api_keys (id, user_id, organization_id, name, description, key_hash, key_prefix, scopes, expires_at, last_used_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err = r.db.ExecContext(ctx, query,
		apiKey.ID,
		apiKey.UserID,
		apiKey.OrganizationID,
		apiKey.Name,
		apiKey.Description,
		apiKey.KeyHash,
		apiKey.KeyPrefix,
		scopesJSON,
		apiKey.ExpiresAt,
		apiKey.LastUsedAt,
		apiKey.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create api key: %w", err)
	}

	return nil
}

// GetAPIKeyByID retrieves an API key by ID.
//
// Returns an error wrapping ErrNotFound when no key has that ID.
func (r *APIKeyRepository) GetAPIKeyByID(ctx context.Context, keyID string) (*models.APIKey, error) {
	query := `
		SELECT id, user_id, organization_id, name, description, key_hash, key_prefix, scopes,
		       expires_at, last_used_at, expiry_notification_sent_at, created_at
		FROM api_keys
		WHERE id = $1
	`

	apiKey, err := scanAPIKey(r.db.QueryRowContext(ctx, query, keyID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound("api key by id")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get api key by id: %w", err)
	}
	return apiKey, nil
}

// ListAPIKeysByUser retrieves all API keys for a user
func (r *APIKeyRepository) ListAPIKeysByUser(ctx context.Context, userID string) ([]*models.APIKey, error) {
	query := `
		SELECT ak.id, ak.user_id, ak.organization_id, ak.name, ak.description, ak.key_hash, ak.key_prefix, ak.scopes,
		       ak.expires_at, ak.last_used_at, ak.expiry_notification_sent_at, ak.created_at, u.name as user_name
		FROM api_keys ak
		LEFT JOIN users u ON ak.user_id = u.id
		WHERE ak.user_id = $1
		ORDER BY ak.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list api keys by user: %w", err)
	}
	defer rows.Close()

	apiKeys := make([]*models.APIKey, 0)
	for rows.Next() {
		apiKey, err := scanAPIKeyWithUserName(rows)
		if err != nil {
			return nil, err
		}
		apiKeys = append(apiKeys, apiKey)
	}

	return apiKeys, rows.Err()
}

// ListAPIKeysByOrganization retrieves all API keys for an organization
func (r *APIKeyRepository) ListAPIKeysByOrganization(ctx context.Context, orgID string) ([]*models.APIKey, error) {
	query := `
		SELECT ak.id, ak.user_id, ak.organization_id, ak.name, ak.description, ak.key_hash, ak.key_prefix, ak.scopes,
		       ak.expires_at, ak.last_used_at, ak.expiry_notification_sent_at, ak.created_at, u.name as user_name
		FROM api_keys ak
		LEFT JOIN users u ON ak.user_id = u.id
		WHERE ak.organization_id = $1
		ORDER BY ak.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list api keys by organization: %w", err)
	}
	defer rows.Close()

	apiKeys := make([]*models.APIKey, 0)
	for rows.Next() {
		apiKey, err := scanAPIKeyWithUserName(rows)
		if err != nil {
			return nil, err
		}
		apiKeys = append(apiKeys, apiKey)
	}

	return apiKeys, rows.Err()
}

// UpdateLastUsed updates the last_used_at timestamp for an API key.
//
// Returns an error wrapping ErrNotFound when no key has that ID — a key
// revoked between authentication and this bookkeeping write. Callers that treat
// last-used tracking as best effort should test for ErrNotFound and ignore it
// rather than failing the request; what they must NOT do is keep receiving a
// nil error for a write that touched nothing.
func (r *APIKeyRepository) UpdateLastUsed(ctx context.Context, keyID string) error {
	query := `
		UPDATE api_keys
		SET last_used_at = $2
		WHERE id = $1
	`

	res, err := r.db.ExecContext(ctx, query, keyID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update api key last used: %w", err)
	}
	return requireRow(res, "api key by id")
}

// RevokeAPIKey deletes/revokes an API key.
//
// Returns an error wrapping ErrNotFound when no key has that ID. Revocation is
// the operation this whole batch exists for: with a wrong, stale or (once
// tenancy predicates land) cross-tenant id, the previous nil return let a
// consuming app tell an operator "API key revoked" and write that to its audit
// log while the credential stayed live.
func (r *APIKeyRepository) RevokeAPIKey(ctx context.Context, keyID string) error {
	query := `DELETE FROM api_keys WHERE id = $1`
	res, err := r.db.ExecContext(ctx, query, keyID)
	if err != nil {
		return fmt.Errorf("failed to revoke api key: %w", err)
	}
	return requireRow(res, "api key by id")
}

// DeleteExpiredKeys deletes all expired API keys (for cleanup/cron job) and
// returns how many it deleted.
//
// This is a bulk sweep, so zero rows is a normal outcome ("nothing had expired")
// and NOT an error — but a caller still has to be able to tell a sweep that
// cleaned up from one that found nothing, which is what the count is for.
// Mirrors DeleteAuditLogsBefore.
func (r *APIKeyRepository) DeleteExpiredKeys(ctx context.Context) (int64, error) {
	query := `
		DELETE FROM api_keys
		WHERE expires_at IS NOT NULL AND expires_at < $1
	`

	res, err := r.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired api keys: %w", err)
	}
	return affectedRows(res, "expired api keys")
}

// GetAPIKeysByPrefix retrieves the non-expired API keys matching a prefix
// (for authentication).
//
// This is the real authentication lookup: callers narrow the candidate set by
// the indexed key_prefix, then bcrypt-compare the presented key against each
// returned candidate's key_hash (see auth.ValidateAPIKey). The query itself
// now excludes expired rows (expires_at IS NULL OR expires_at > NOW()) so
// expiry enforcement lives at the shared-library level instead of depending
// on every caller remembering to re-check ExpiresAt after the fact. Any
// caller that additionally checks ExpiresAt on the returned keys is now
// performing a harmless redundant second check.
func (r *APIKeyRepository) GetAPIKeysByPrefix(ctx context.Context, keyPrefix string) ([]*models.APIKey, error) {
	query := `
		SELECT id, user_id, organization_id, name, description, key_hash, key_prefix, scopes,
		       expires_at, last_used_at, expiry_notification_sent_at, created_at
		FROM api_keys
		WHERE key_prefix = $1
		  AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, keyPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to get api keys by prefix: %w", err)
	}
	defer rows.Close()

	apiKeys := make([]*models.APIKey, 0)
	for rows.Next() {
		apiKey, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		apiKeys = append(apiKeys, apiKey)
	}

	return apiKeys, rows.Err()
}

// FindExpiringKeys returns API keys that will expire within warningDays days
// and have not yet had a notification email sent (expiry_notification_sent_at IS NULL).
// Only keys associated with a user (user_id IS NOT NULL) are returned so the caller
// can look up an email address.
func (r *APIKeyRepository) FindExpiringKeys(ctx context.Context, warningDays int) ([]*models.APIKey, error) {
	cutoff := time.Now().Add(time.Duration(warningDays) * 24 * time.Hour)
	// expiry_notification_sent_at is selected (though the WHERE clause guarantees
	// it's NULL for every matching row) purely so this query shares scanAPIKey's
	// column projection.
	query := `
		SELECT id, user_id, organization_id, name, description, key_hash, key_prefix, scopes,
		       expires_at, last_used_at, expiry_notification_sent_at, created_at
		FROM api_keys
		WHERE expires_at IS NOT NULL
		  AND expires_at > NOW()
		  AND expires_at <= $1
		  AND expiry_notification_sent_at IS NULL
		  AND user_id IS NOT NULL
		ORDER BY expires_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, cutoff)
	if err != nil {
		return nil, fmt.Errorf("failed to find expiring api keys: %w", err)
	}
	defer rows.Close()

	keys := make([]*models.APIKey, 0)
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// ClaimExpiryNotification atomically claims the right to send the expiry warning
// for a key: it sets expiry_notification_sent_at only if it is still NULL, and
// reports whether THIS call won the claim. Under horizontal scaling several
// replicas run the notifier concurrently; gating the send on a winning claim
// (claim-then-send) is what stops them all emailing the same key, since the
// conditional UPDATE is atomic and exactly one row update takes effect.
//
// A caller that wins the claim but then fails to send has recorded a "sent" it
// did not deliver — a missed notice, deliberately preferred over the duplicate
// spam a send-then-mark ordering produces across replicas.
func (r *APIKeyRepository) ClaimExpiryNotification(ctx context.Context, keyID string) (bool, error) {
	query := `UPDATE api_keys SET expiry_notification_sent_at = $1
	          WHERE id = $2 AND expiry_notification_sent_at IS NULL`
	res, err := r.db.ExecContext(ctx, query, time.Now(), keyID)
	if err != nil {
		return false, fmt.Errorf("failed to claim api key expiry notification: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to read claim result for api key expiry notification: %w", err)
	}
	return n > 0, nil
}

// Update updates an API key's information.
//
// Returns an error wrapping ErrNotFound when no key has apiKey.ID.
func (r *APIKeyRepository) Update(ctx context.Context, apiKey *models.APIKey) error {
	// Marshal scopes to JSONB
	scopesJSON, err := json.Marshal(apiKey.Scopes)
	if err != nil {
		return fmt.Errorf("failed to marshal api key scopes: %w", err)
	}

	query := `
		UPDATE api_keys
		SET name = $2, description = $3, scopes = $4, expires_at = $5
		WHERE id = $1
	`

	res, err := r.db.ExecContext(ctx, query,
		apiKey.ID,
		apiKey.Name,
		apiKey.Description,
		scopesJSON,
		apiKey.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update api key: %w", err)
	}

	return requireRow(res, "api key by id")
}

// ListByUserAndOrganization retrieves API keys for a specific user within a specific organization
func (r *APIKeyRepository) ListByUserAndOrganization(ctx context.Context, userID, orgID string) ([]*models.APIKey, error) {
	query := `
		SELECT ak.id, ak.user_id, ak.organization_id, ak.name, ak.description, ak.key_hash, ak.key_prefix, ak.scopes,
		       ak.expires_at, ak.last_used_at, ak.expiry_notification_sent_at, ak.created_at, u.name as user_name
		FROM api_keys ak
		LEFT JOIN users u ON ak.user_id = u.id
		WHERE ak.user_id = $1 AND ak.organization_id = $2
		ORDER BY ak.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list api keys by user and organization: %w", err)
	}
	defer rows.Close()

	apiKeys := make([]*models.APIKey, 0)
	for rows.Next() {
		apiKey, err := scanAPIKeyWithUserName(rows)
		if err != nil {
			return nil, err
		}
		apiKeys = append(apiKeys, apiKey)
	}

	return apiKeys, rows.Err()
}

// ListAll retrieves all API keys across all organizations (for admin use)
func (r *APIKeyRepository) ListAll(ctx context.Context) ([]*models.APIKey, error) {
	query := `
		SELECT ak.id, ak.user_id, ak.organization_id, ak.name, ak.description, ak.key_hash, ak.key_prefix, ak.scopes,
		       ak.expires_at, ak.last_used_at, ak.expiry_notification_sent_at, ak.created_at, u.name as user_name
		FROM api_keys ak
		LEFT JOIN users u ON ak.user_id = u.id
		ORDER BY ak.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list all api keys: %w", err)
	}
	defer rows.Close()

	allKeys := make([]*models.APIKey, 0)
	for rows.Next() {
		apiKey, err := scanAPIKeyWithUserName(rows)
		if err != nil {
			return nil, err
		}
		allKeys = append(allKeys, apiKey)
	}

	return allKeys, rows.Err()
}
