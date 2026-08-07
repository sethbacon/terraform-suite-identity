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

// CreateAPIKey creates a new API key in apiKey.OrganizationID.
//
// scope is the mandatory tenant constraint. The create axis has no existing row
// to filter, so the predicate is applied to the organizations table instead: the
// INSERT sources its rows from a SELECT over the named organization, and that
// SELECT carries the scope. An organization outside the scope (or one that does
// not exist) therefore inserts nothing and reports ErrNotFound — the same
// answer, and the same statement shape, as an out-of-scope by-id mutation.
//
// Reporting a refused create as ErrNotFound rather than as a distinct
// "forbidden" sentinel is deliberate and uniform across every scoped accessor
// here: a caller able to distinguish "exists but not yours" from "does not
// exist" has an existence oracle over other tenants' organization ids, which is
// the disclosure half of the very class this parameter closes.
func (r *APIKeyRepository) CreateAPIKey(ctx context.Context, apiKey *models.APIKey, scope OrgScope) error {
	apiKey.ID = uuid.New().String()
	apiKey.CreatedAt = time.Now()

	// Marshal scopes to JSONB
	scopesJSON, err := json.Marshal(apiKey.Scopes)
	if err != nil {
		return fmt.Errorf("failed to marshal api key scopes: %w", err)
	}

	if scope.MatchesNothing() {
		return notFound("api key organization")
	}

	// GUARD org-scope-apikey-create (issue #138). The scope constrains the
	// organizations row the INSERT selects from, so an out-of-scope (or absent)
	// organization inserts zero rows rather than being rejected only by the
	// foreign key.
	query := `
		INSERT INTO api_keys (id, user_id, organization_id, name, description, key_hash, key_prefix, scopes, expires_at, last_used_at, created_at)
		SELECT $1, $2, o.id, $4, $5, $6, $7, $8, $9, $10, $11
		FROM organizations o
		WHERE o.id = $3
	`
	args := []interface{}{
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
	}
	query, args = andScope(query, scope, "o.id", args)

	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to create api key: %w", err)
	}

	return requireRow(res, "api key organization")
}

// GetAPIKeyByID retrieves an API key by ID within scope.
//
// Returns an error wrapping ErrNotFound when no key has that ID *inside the
// scope* — the SAME error a genuinely absent key produces, so the by-id read
// cannot be used to probe whether an id exists in another tenant.
//
// This is the read half of #138. The row this returns includes key_hash, so an
// unscoped by-id read handed any organization's credential digest to any caller
// that could name a UUID — which is exactly what a handler binding a path
// parameter does.
func (r *APIKeyRepository) GetAPIKeyByID(ctx context.Context, keyID string, scope OrgScope) (*models.APIKey, error) {
	if scope.MatchesNothing() {
		return nil, notFound("api key by id")
	}

	// GUARD org-scope-apikey-byid (issue #138).
	query := `
		SELECT id, user_id, organization_id, name, description, key_hash, key_prefix, scopes,
		       expires_at, last_used_at, expiry_notification_sent_at, created_at
		FROM api_keys
		WHERE id = $1
	`
	args := []interface{}{keyID}
	query, args = andScope(query, scope, "organization_id", args)

	apiKey, err := scanAPIKey(r.db.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound("api key by id")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get api key by id: %w", err)
	}
	return apiKey, nil
}

// ListAPIKeysByUser retrieves a user's API keys within scope.
//
// Without the scope this returned every organization's keys for that user, so
// an administrator of one organization enumerating a user saw the credentials
// that user holds in organizations the administrator has no relationship with —
// the list axis of the same disclosure #161 reports for organizations.
func (r *APIKeyRepository) ListAPIKeysByUser(ctx context.Context, userID string, scope OrgScope) ([]*models.APIKey, error) {
	if scope.MatchesNothing() {
		return []*models.APIKey{}, nil
	}

	// GUARD org-scope-apikey-list (issue #138).
	query := `
		SELECT ak.id, ak.user_id, ak.organization_id, ak.name, ak.description, ak.key_hash, ak.key_prefix, ak.scopes,
		       ak.expires_at, ak.last_used_at, ak.expiry_notification_sent_at, ak.created_at, u.name as user_name
		FROM api_keys ak
		LEFT JOIN users u ON ak.user_id = u.id
		WHERE ak.user_id = $1
	`
	args := []interface{}{userID}
	query, args = andScope(query, scope, "ak.organization_id", args)
	query += ` ORDER BY ak.created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, args...)
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

// ListAPIKeysByOrganization retrieves an organization's API keys within scope.
//
// The orgID argument names WHICH organization to list; scope states which
// organizations the caller may reach. They are not the same statement and
// collapsing them is how this class starts: an orgID bound from a path
// parameter is caller-controlled input, not authority. An orgID outside the
// scope yields an empty list.
func (r *APIKeyRepository) ListAPIKeysByOrganization(ctx context.Context, orgID string, scope OrgScope) ([]*models.APIKey, error) {
	if scope.MatchesNothing() {
		return []*models.APIKey{}, nil
	}

	// GUARD org-scope-apikey-list (issue #138).
	query := `
		SELECT ak.id, ak.user_id, ak.organization_id, ak.name, ak.description, ak.key_hash, ak.key_prefix, ak.scopes,
		       ak.expires_at, ak.last_used_at, ak.expiry_notification_sent_at, ak.created_at, u.name as user_name
		FROM api_keys ak
		LEFT JOIN users u ON ak.user_id = u.id
		WHERE ak.organization_id = $1
	`
	args := []interface{}{orgID}
	query, args = andScope(query, scope, "ak.organization_id", args)
	query += ` ORDER BY ak.created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, args...)
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
// UNSCOPED BY DESIGN — authentication bookkeeping on the caller's OWN row.
// keyID here comes from the key that just authenticated, not from a request
// path, so there is no cross-tenant id for a scope to reject; and this runs on
// the authentication hot path, before any scope has been resolved.
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

// RevokeAPIKey deletes/revokes an API key within scope.
//
// Returns an error wrapping ErrNotFound when no key has that ID inside the
// scope. Revocation is
// the operation this whole batch exists for: with a wrong, stale or (once
// tenancy predicates land) cross-tenant id, the previous nil return let a
// consuming app tell an operator "API key revoked" and write that to its audit
// log while the credential stayed live.
func (r *APIKeyRepository) RevokeAPIKey(ctx context.Context, keyID string, scope OrgScope) error {
	if scope.MatchesNothing() {
		return notFound("api key by id")
	}

	// GUARD org-scope-apikey-delete (issue #138).
	query := `DELETE FROM api_keys WHERE id = $1`
	args := []interface{}{keyID}
	query, args = andScope(query, scope, "organization_id", args)

	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to revoke api key: %w", err)
	}
	return requireRow(res, "api key by id")
}

// RevokeAPIKeysForUser deletes every API key userID holds INSIDE scope and
// returns how many it deleted.
//
// # Why this exists (issues #160 and #162, co-designed)
//
// SCIM deactivation does two things in one request: it strips the target's
// organization memberships, and it revokes the credentials those memberships
// backed. Before v0.25.0 the two halves disagreed about tenancy. The registry's
// membership strip was tenant-scoped (its #719); the credential sweep beside it
// reached RevokeAPIKey per key with no scope at all, so a caller holding
// scim:provision through membership in ONE organization irreversibly deleted
// api_keys rows owned by organizations they had no relationship with.
//
// Narrowing the sweep must not reintroduce the STRANDED CREDENTIAL defect that
// motivated the sweep in the first place (#732/#736): a key that outlives the
// authority it was issued under keeps working from a stale snapshot. The
// resolution is that the two halves share one scope, derived from the first:
//
//	removed, err := orgRepo.RemoveAllMembershipsForUser(ctx, userID, scope)
//	...
//	n, err := keyRepo.RevokeAPIKeysForUser(ctx, userID, removed)
//
// RemoveAllMembershipsForUser returns, as an OrgScope, the organizations whose
// membership it ACTUALLY removed — not the organizations the caller asked
// about. Feeding that into the sweep makes the invariant structural rather than
// remembered: a key is revoked exactly when the authority behind it was just
// withdrawn, in the same organization, in the same request. No membership
// removed in an organization means no authority reduced there, so nothing is
// stranded by leaving that organization's keys alone; and every organization
// where authority WAS reduced is, by construction, in the sweep's scope.
//
// Returning an OrgScope from the strip rather than a []string is what closes
// the seam: the value the sweep needs is the value the strip produces, in the
// type the sweep demands, so a consumer cannot pass the wrong set without
// writing a different expression on purpose.
//
// Bulk, so zero is not an error: an empty removed-scope short-circuits to
// (0, nil) without a round trip.
func (r *APIKeyRepository) RevokeAPIKeysForUser(ctx context.Context, userID string, scope OrgScope) (int64, error) {
	if scope.MatchesNothing() {
		return 0, nil
	}

	// GUARD org-scope-apikey-sweep (issues #160, #162).
	query := `DELETE FROM api_keys WHERE user_id = $1`
	args := []interface{}{userID}
	query, args = andScope(query, scope, "organization_id", args)

	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to revoke api keys for user: %w", err)
	}
	return affectedRows(res, "api keys for user")
}

// DeleteExpiredKeys deletes all expired API keys (for cleanup/cron job) and
// returns how many it deleted.
//
// UNSCOPED BY DESIGN — unattended maintenance. There is no principal on this
// path to resolve a scope from, and an expired key is expired in every
// organization; a tenant predicate here would leave other tenants' expired rows
// accumulating forever and would need a caller that does not exist.
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
// UNSCOPED BY DESIGN — authority derivation. This is the lookup that decides
// WHO the caller is; requiring a scope would be circular, since the scope is
// derived from the principal this call establishes. The presented credential is
// the authority: a caller reaches a row here only by proving knowledge of the
// key whose bcrypt digest that row holds.
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

// FindExpiringKeys returns API keys that will expire within warningDays days.
//
// UNSCOPED BY DESIGN — unattended maintenance, like DeleteExpiredKeys. The
// notifier is a background job with no principal, and it emails the key's own
// owner rather than exposing rows to a requester.
//
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

// ClaimExpiryNotification atomically claims the right to send the expiry
// warning.
//
// UNSCOPED BY DESIGN — the keyID comes from FindExpiringKeys in the same
// background job, never from a request.
//
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

// Update updates an API key's information within scope.
//
// Returns an error wrapping ErrNotFound when no key has apiKey.ID inside the
// scope. This is the escalation axis of #138: the statement rewrites `scopes`
// and `expires_at`, so an unscoped update let a caller holding any single
// organization's key-management authority widen the permissions of, or
// indefinitely extend, another organization's credential.
//
// apiKey.OrganizationID is NOT consulted here — the predicate reads the stored
// row's owner. A caller cannot move a key between organizations by editing the
// struct, and cannot reach another tenant's row by claiming its id.
func (r *APIKeyRepository) Update(ctx context.Context, apiKey *models.APIKey, scope OrgScope) error {
	if scope.MatchesNothing() {
		return notFound("api key by id")
	}

	// Marshal scopes to JSONB
	scopesJSON, err := json.Marshal(apiKey.Scopes)
	if err != nil {
		return fmt.Errorf("failed to marshal api key scopes: %w", err)
	}

	// GUARD org-scope-apikey-update (issue #138).
	query := `
		UPDATE api_keys
		SET name = $2, description = $3, scopes = $4, expires_at = $5
		WHERE id = $1
	`
	args := []interface{}{
		apiKey.ID,
		apiKey.Name,
		apiKey.Description,
		scopesJSON,
		apiKey.ExpiresAt,
	}
	query, args = andScope(query, scope, "organization_id", args)

	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update api key: %w", err)
	}

	return requireRow(res, "api key by id")
}

// ListByUserAndOrganization retrieves a user's API keys in one organization,
// within scope.
//
// As on ListAPIKeysByOrganization, orgID names the organization asked about and
// scope names the organizations the caller may reach; an orgID outside the scope
// yields an empty list rather than the organization's keys.
func (r *APIKeyRepository) ListByUserAndOrganization(ctx context.Context, userID, orgID string, scope OrgScope) ([]*models.APIKey, error) {
	if scope.MatchesNothing() {
		return []*models.APIKey{}, nil
	}

	// GUARD org-scope-apikey-list (issue #138).
	query := `
		SELECT ak.id, ak.user_id, ak.organization_id, ak.name, ak.description, ak.key_hash, ak.key_prefix, ak.scopes,
		       ak.expires_at, ak.last_used_at, ak.expiry_notification_sent_at, ak.created_at, u.name as user_name
		FROM api_keys ak
		LEFT JOIN users u ON ak.user_id = u.id
		WHERE ak.user_id = $1 AND ak.organization_id = $2
	`
	args := []interface{}{userID, orgID}
	query, args = andScope(query, scope, "ak.organization_id", args)
	query += ` ORDER BY ak.created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, args...)
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

// ListAPIKeys retrieves the API keys inside scope.
//
// It was called ListAll until v0.25.0, when it gained the scope parameter. The
// old name would then have been a lie in the common case — `ListAll(ctx,
// OrgScopeOrganizations("a"))` reads as a contradiction — and a lying name on
// an admin-facing enumeration is how a reviewer skips the call site. Pass
// OrgScopeAllOrganizations() for the genuine platform-wide listing.
//
// Both consumers previously filtered this result in memory against a
// hand-computed admin-organization set; that filter is now the query's own
// predicate, which no caller-supplied argument can bypass.
func (r *APIKeyRepository) ListAPIKeys(ctx context.Context, scope OrgScope) ([]*models.APIKey, error) {
	if scope.MatchesNothing() {
		return []*models.APIKey{}, nil
	}

	// GUARD org-scope-apikey-list (issue #138).
	query := `
		SELECT ak.id, ak.user_id, ak.organization_id, ak.name, ak.description, ak.key_hash, ak.key_prefix, ak.scopes,
		       ak.expires_at, ak.last_used_at, ak.expiry_notification_sent_at, ak.created_at, u.name as user_name
		FROM api_keys ak
		LEFT JOIN users u ON ak.user_id = u.id
		WHERE 1=1
	`
	var args []interface{}
	query, args = andScope(query, scope, "ak.organization_id", args)
	query += ` ORDER BY ak.created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list api keys: %w", err)
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
