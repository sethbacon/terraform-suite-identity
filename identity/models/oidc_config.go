package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// OIDCConfig holds OIDC provider configuration stored in the database. Sensitive
// fields use the _encrypted suffix and are hidden from JSON.
//
// Only the persisted identity shape and its data helpers live in the module;
// API request/response DTOs and setup-wizard state are owned by each app.
type OIDCConfig struct {
	ID                    uuid.UUID       `db:"id" json:"id"`
	Name                  string          `db:"name" json:"name"`
	ProviderType          string          `db:"provider_type" json:"provider_type"`
	IssuerURL             string          `db:"issuer_url" json:"issuer_url"`
	ClientID              string          `db:"client_id" json:"client_id"`
	ClientSecretEncrypted string          `db:"client_secret_encrypted" json:"-"` // Never expose
	RedirectURL           string          `db:"redirect_url" json:"redirect_url"`
	Scopes                json.RawMessage `db:"scopes" json:"scopes"`
	IsActive              bool            `db:"is_active" json:"is_active"`
	ExtraConfig           json.RawMessage `db:"extra_config" json:"extra_config,omitempty"`
	CreatedAt             time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt             time.Time       `db:"updated_at" json:"updated_at"`
	CreatedBy             uuid.NullUUID   `db:"created_by" json:"created_by,omitempty"`
	UpdatedBy             uuid.NullUUID   `db:"updated_by" json:"updated_by,omitempty"`
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
// standard OIDC scopes when empty.
func (c *OIDCConfig) GetScopes() []string {
	var scopes []string
	if len(c.Scopes) > 0 {
		_ = json.Unmarshal(c.Scopes, &scopes) // nolint:errcheck
	}
	if len(scopes) == 0 {
		return []string{"openid", "email", "profile"}
	}
	return scopes
}
