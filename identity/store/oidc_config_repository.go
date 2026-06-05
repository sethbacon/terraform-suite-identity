package store

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// OIDCConfigRepository is the data-access layer for stored OIDC configuration
// and the system_settings key-value store (setup state and token hash).
type OIDCConfigRepository struct {
	db *sqlx.DB
}

// NewOIDCConfigRepository constructs an OIDCConfigRepository over the given connection.
func NewOIDCConfigRepository(db *sqlx.DB) *OIDCConfigRepository {
	return &OIDCConfigRepository{db: db}
}

func (r *OIDCConfigRepository) GetActiveOIDCConfig(ctx context.Context) (*models.OIDCConfig, error) {
	var cfg models.OIDCConfig
	err := r.db.GetContext(ctx, &cfg, "SELECT * FROM oidc_config WHERE is_active = true LIMIT 1")
	if err != nil {
		return nil, fmt.Errorf("failed to get active OIDC config: %w", err)
	}
	return &cfg, nil
}

func (r *OIDCConfigRepository) SaveOIDCConfig(ctx context.Context, cfg *models.OIDCConfig) error {
	// Deactivate existing configs.
	_, err := r.db.ExecContext(ctx, "UPDATE oidc_config SET is_active = false WHERE is_active = true")
	if err != nil {
		return fmt.Errorf("failed to deactivate existing OIDC configs: %w", err)
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO oidc_config (issuer_url, client_id, client_secret_encrypted, redirect_url, scopes, is_active)
         VALUES ($1, $2, $3, $4, $5, true)`,
		cfg.IssuerURL, cfg.ClientID, cfg.ClientSecretEncrypted, cfg.RedirectURL, cfg.ScopesJSON,
	)
	if err != nil {
		return fmt.Errorf("failed to save OIDC config: %w", err)
	}
	return nil
}

func (r *OIDCConfigRepository) IsSetupCompleted(ctx context.Context) (bool, error) {
	var value string
	err := r.db.GetContext(ctx, &value, "SELECT value FROM system_settings WHERE key = 'setup_completed'")
	if err != nil {
		return false, nil // Default to not completed.
	}
	return value == "true", nil
}

func (r *OIDCConfigRepository) SetSetupCompleted(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO system_settings (key, value, updated_at) VALUES ('setup_completed', 'true', NOW())
         ON CONFLICT (key) DO UPDATE SET value = 'true', updated_at = NOW()`)
	if err != nil {
		return fmt.Errorf("failed to set setup completed: %w", err)
	}
	return nil
}

func (r *OIDCConfigRepository) GetSetupTokenHash(ctx context.Context) (string, error) {
	var value string
	err := r.db.GetContext(ctx, &value, "SELECT value FROM system_settings WHERE key = 'setup_token_hash'")
	if err != nil {
		return "", nil // No token hash exists.
	}
	return value, nil
}

func (r *OIDCConfigRepository) SetSetupTokenHash(ctx context.Context, hash string) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO system_settings (key, value, updated_at) VALUES ('setup_token_hash', $1, NOW())
         ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()`,
		hash,
	)
	if err != nil {
		return fmt.Errorf("failed to set setup token hash: %w", err)
	}
	return nil
}
