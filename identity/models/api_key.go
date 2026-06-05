package models

import "time"

// APIKey represents an API key for authentication.
//
// A key is usable while it exists and has not passed ExpiresAt. Revocation is a
// hard delete (there is no soft-active flag); expiry warnings are tracked via
// ExpiryNotificationSentAt.
type APIKey struct {
	ID                       string     `json:"id"`
	UserID                   *string    `json:"user_id,omitempty"`
	OrganizationID           string     `json:"organization_id"`
	Name                     string     `json:"name"`
	Description              *string    `json:"description,omitempty"`
	KeyHash                  string     `json:"key_hash"`
	KeyPrefix                string     `json:"key_prefix"`
	Scopes                   []string   `json:"scopes"`
	ExpiresAt                *time.Time `json:"expires_at,omitempty"`
	LastUsedAt               *time.Time `json:"last_used_at,omitempty"`
	ExpiryNotificationSentAt *time.Time `json:"expiry_notification_sent_at,omitempty"`
	CreatedAt                time.Time  `json:"created_at"`
	// Joined fields (not stored in api_keys table)
	UserName *string `json:"user_name,omitempty"`
}
