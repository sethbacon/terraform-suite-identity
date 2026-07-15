// oidc_config_repository.go implements OIDCConfigRepository, providing database
// queries for reading, creating, and managing OIDC provider configurations
// stored in the identity schema.
//
// This is the identity half only: OIDC-config CRUD. Setup-wizard state (setup
// token, scanning/LDAP config, auth method, setup status) is app-specific and
// owned by each consuming app, not the shared identity module.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// OIDCConfigRepository handles database operations for OIDC configuration.
type OIDCConfigRepository struct {
	db *sqlx.DB
}

// NewOIDCConfigRepository creates a new OIDC configuration repository.
func NewOIDCConfigRepository(db *sqlx.DB) *OIDCConfigRepository {
	return &OIDCConfigRepository{db: db}
}

// createOIDCConfigInsertQuery is the shared INSERT statement used by both the
// plain (inactive) and transactional (active) create paths in CreateOIDCConfig.
const createOIDCConfigInsertQuery = `
	INSERT INTO oidc_config (
		id, name, provider_type, issuer_url, client_id, client_secret_encrypted,
		redirect_url, scopes, is_active, extra_config,
		created_at, updated_at, created_by, updated_by
	) VALUES (
		$1, $2, $3, $4, $5, $6,
		$7, $8, $9, $10,
		$11, $12, $13, $14
	)`

// CreateOIDCConfig creates a new OIDC configuration.
//
// If config.IsActive is true, the insert is wrapped in the same
// deactivate-all-then-activate-one transaction that ActivateOIDCConfig uses,
// so a config can never be created active while another active row still
// exists (the single-active-config invariant is enforced at write time, not
// just by convention). If config.IsActive is false, this is a plain,
// untransacted insert — behavior is unchanged from before.
func (r *OIDCConfigRepository) CreateOIDCConfig(ctx context.Context, config *models.OIDCConfig) error {
	if !config.IsActive {
		_, err := r.db.ExecContext(ctx, createOIDCConfigInsertQuery,
			config.ID, config.Name, config.ProviderType, config.IssuerURL, config.ClientID,
			config.ClientSecretCiphertext,
			config.RedirectURL, config.Scopes, config.IsActive, config.ExtraConfig,
			config.CreatedAt, config.UpdatedAt, config.CreatedBy, config.UpdatedBy,
		)
		if err != nil {
			return fmt.Errorf("failed to create oidc config: %w", err)
		}
		return nil
	}

	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction creating active oidc config: %w", err)
	}
	defer tx.Rollback() // nolint:errcheck

	if err := deactivateAllOIDCConfigsTx(ctx, tx); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, createOIDCConfigInsertQuery,
		config.ID, config.Name, config.ProviderType, config.IssuerURL, config.ClientID,
		config.ClientSecretCiphertext,
		config.RedirectURL, config.Scopes, config.IsActive, config.ExtraConfig,
		config.CreatedAt, config.UpdatedAt, config.CreatedBy, config.UpdatedBy,
	); err != nil {
		return fmt.Errorf("failed to create active oidc config: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit active oidc config creation: %w", err)
	}
	return nil
}

// oidcConfigColumns is the explicit column projection for oidc_config reads.
// extra_config is COALESCEd to '{}' so a NULL JSONB value does not fail the scan
// into the model's non-nullable json.RawMessage ExtraConfig field (a bare
// SELECT * errors when extra_config is NULL). The AS alias keeps the column name
// so sqlx still maps it.
const oidcConfigColumns = `id, name, provider_type, issuer_url, client_id, ` +
	`client_secret_encrypted, redirect_url, scopes, is_active, ` +
	`COALESCE(extra_config, '{}'::jsonb) AS extra_config, ` +
	`created_at, updated_at, created_by, updated_by`

// GetActiveOIDCConfig retrieves the currently active OIDC configuration.
//
// The query orders by updated_at DESC as a defensive, deterministic tie-break:
// the schema now enforces at most one is_active=true row via a partial unique
// index (see migration 000005), but the ORDER BY keeps behavior deterministic
// even against an older database that hasn't run that migration yet.
func (r *OIDCConfigRepository) GetActiveOIDCConfig(ctx context.Context) (*models.OIDCConfig, error) {
	var config models.OIDCConfig
	query := `SELECT ` + oidcConfigColumns + ` FROM oidc_config WHERE is_active = true ORDER BY updated_at DESC LIMIT 1`
	err := r.db.GetContext(ctx, &config, query)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get active oidc config: %w", err)
	}
	return &config, nil
}

// GetOIDCConfig retrieves an OIDC configuration by ID.
func (r *OIDCConfigRepository) GetOIDCConfig(ctx context.Context, id uuid.UUID) (*models.OIDCConfig, error) {
	var config models.OIDCConfig
	query := `SELECT ` + oidcConfigColumns + ` FROM oidc_config WHERE id = $1`
	err := r.db.GetContext(ctx, &config, query, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get oidc config %s: %w", id, err)
	}
	return &config, nil
}

// ListOIDCConfigs lists all OIDC configurations.
func (r *OIDCConfigRepository) ListOIDCConfigs(ctx context.Context) ([]*models.OIDCConfig, error) {
	var configs []*models.OIDCConfig
	query := `SELECT ` + oidcConfigColumns + ` FROM oidc_config ORDER BY created_at DESC`
	err := r.db.SelectContext(ctx, &configs, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list oidc configs: %w", err)
	}
	return configs, nil
}

// DeleteOIDCConfig deletes an OIDC configuration.
func (r *OIDCConfigRepository) DeleteOIDCConfig(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM oidc_config WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete oidc config %s: %w", id, err)
	}
	return nil
}

// UpdateOIDCConfigExtraConfig updates only the extra_config column (used for group mapping settings).
func (r *OIDCConfigRepository) UpdateOIDCConfigExtraConfig(ctx context.Context, id uuid.UUID, extraConfig []byte) error {
	query := `UPDATE oidc_config SET extra_config = $1, updated_at = $2 WHERE id = $3`
	_, err := r.db.ExecContext(ctx, query, extraConfig, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update oidc config %s extra_config: %w", id, err)
	}
	return nil
}

// DeactivateAllOIDCConfigs sets is_active=false for all configurations.
func (r *OIDCConfigRepository) DeactivateAllOIDCConfigs(ctx context.Context) error {
	query := `UPDATE oidc_config SET is_active = false, updated_at = $1`
	_, err := r.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to deactivate oidc configs: %w", err)
	}
	return nil
}

// deactivateAllOIDCConfigsTx sets is_active=false for all configurations
// within an already-open transaction. It is the shared "deactivate all" step
// of the single-active-config invariant, used by both ActivateOIDCConfig and
// CreateOIDCConfig (when creating an already-active config) so exactly one
// row can be active at commit time.
func deactivateAllOIDCConfigsTx(ctx context.Context, tx *sqlx.Tx) error {
	_, err := tx.ExecContext(ctx, `UPDATE oidc_config SET is_active = false, updated_at = $1`, time.Now())
	if err != nil {
		return fmt.Errorf("failed to deactivate oidc configs: %w", err)
	}
	return nil
}

// ActivateOIDCConfig activates a specific configuration (deactivates others first).
func (r *OIDCConfigRepository) ActivateOIDCConfig(ctx context.Context, id uuid.UUID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction activating oidc config %s: %w", id, err)
	}
	defer tx.Rollback() // nolint:errcheck

	if err := deactivateAllOIDCConfigsTx(ctx, tx); err != nil {
		return err
	}

	// Activate the specified config
	_, err = tx.ExecContext(ctx,
		`UPDATE oidc_config SET is_active = true, updated_at = $1 WHERE id = $2`,
		time.Now(), id,
	)
	if err != nil {
		return fmt.Errorf("failed to activate oidc config %s: %w", id, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit activation of oidc config %s: %w", id, err)
	}
	return nil
}
