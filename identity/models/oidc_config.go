package models

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// OIDCConfig holds OIDC provider configuration stored in the database.
//
// This module performs NO cryptography: ClientSecretCiphertext is stored and
// returned verbatim. A caller that requires encryption at rest must encrypt the
// client secret before persisting and decrypt after reading — the module does
// not own an encryption key. (The database column keeps its historical
// client_secret_encrypted name.)
//
// Only the persisted identity shape and its data helpers live in the module;
// API request/response DTOs and setup-wizard state are owned by each app.
type OIDCConfig struct {
	ID                     uuid.UUID       `db:"id" json:"id"`
	Name                   string          `db:"name" json:"name"`
	ProviderType           string          `db:"provider_type" json:"provider_type"`
	IssuerURL              string          `db:"issuer_url" json:"issuer_url"`
	ClientID               string          `db:"client_id" json:"client_id"`
	ClientSecretCiphertext string          `db:"client_secret_encrypted" json:"-"` // caller-supplied; module does no crypto
	RedirectURL            string          `db:"redirect_url" json:"redirect_url"`
	Scopes                 json.RawMessage `db:"scopes" json:"scopes"`
	IsActive               bool            `db:"is_active" json:"is_active"`
	ExtraConfig            json.RawMessage `db:"extra_config" json:"extra_config,omitempty"`
	CreatedAt              time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt              time.Time       `db:"updated_at" json:"updated_at"`
	CreatedBy              uuid.NullUUID   `db:"created_by" json:"created_by,omitempty"`
	UpdatedBy              uuid.NullUUID   `db:"updated_by" json:"updated_by,omitempty"`
}

// OIDCGroupMapping maps a single IdP group claim value to an organization and role template.
type OIDCGroupMapping struct {
	Group        string `json:"group"`
	Organization string `json:"organization"`
	Role         string `json:"role"`
}

// groupMappingExtra is the shape of the group-mapping keys inside ExtraConfig.
type groupMappingExtra struct {
	GroupClaimName string             `json:"group_claim_name"`
	GroupMappings  []OIDCGroupMapping `json:"group_mappings"`
	DefaultRole    string             `json:"default_role"`
}

// GetGroupMappingConfig reads group mapping settings from ExtraConfig.
func (c *OIDCConfig) GetGroupMappingConfig() (claimName string, mappings []OIDCGroupMapping, defaultRole string) {
	if len(c.ExtraConfig) == 0 {
		return
	}
	var extra groupMappingExtra
	if err := json.Unmarshal(c.ExtraConfig, &extra); err != nil {
		return
	}
	return extra.GroupClaimName, extra.GroupMappings, extra.DefaultRole
}

// SetGroupMappingConfig stores group mapping settings into ExtraConfig, preserving
// any unrelated keys that may already be present.
func (c *OIDCConfig) SetGroupMappingConfig(claimName string, mappings []OIDCGroupMapping, defaultRole string) error {
	// Decode existing extra config to preserve unknown keys.
	existing := make(map[string]interface{})
	if len(c.ExtraConfig) > 0 {
		if err := json.Unmarshal(c.ExtraConfig, &existing); err != nil {
			return err
		}
	}
	existing["group_claim_name"] = claimName
	existing["group_mappings"] = mappings
	existing["default_role"] = defaultRole
	b, err := json.Marshal(existing)
	if err != nil {
		return err
	}
	c.ExtraConfig = json.RawMessage(b)
	return nil
}

// GetScopes parses and returns the scopes as a string slice, defaulting to the
// standard OIDC scopes when the column is empty or holds an empty list.
//
// It returns an error when the scopes column does not decode as a JSON string
// array. Until v0.24.0 that error was discarded behind a `// nolint:errcheck`,
// so a corrupted or hand-edited scopes value fell back to the defaults exactly
// as if the column had been empty — the same "nothing matched is
// indistinguishable from success" shape the store's accessors carried, and one
// that silently narrows the scopes an OIDC login requests.
//
// The defaults are returned ALONGSIDE the error so a caller that decides a
// broken column should not take SSO down can still proceed with a usable value;
// what it can no longer do is proceed without knowing. models is a pure data
// package with no logger of its own, so an error return — not a log line — is
// the only way it can report this.
func (c *OIDCConfig) GetScopes() ([]string, error) {
	defaults := []string{"openid", "email", "profile"}
	var scopes []string
	if len(c.Scopes) > 0 {
		if err := json.Unmarshal(c.Scopes, &scopes); err != nil {
			return defaults, fmt.Errorf("failed to parse oidc config scopes: %w", err)
		}
	}
	if len(scopes) == 0 {
		return defaults, nil
	}
	return scopes, nil
}
