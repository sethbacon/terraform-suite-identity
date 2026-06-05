package models

import "time"

// Organization represents an organization/namespace (tenant).
type Organization struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`         // URL-safe name (used in namespaces)
	DisplayName string    `json:"display_name"` // Human-readable display name
	IdpType     *string   `json:"idp_type"`     // Bound IdP type: "oidc", "saml", "ldap", or nil (no restriction)
	IdpName     *string   `json:"idp_name"`     // Bound IdP name within the type (e.g., SAML IdP name)
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
