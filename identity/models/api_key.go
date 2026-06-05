package models

import "time"

// APIKey is a stored API key record. KeyHash holds the bcrypt hash; the full
// key value is never persisted.
type APIKey struct {
	ID             string     `db:"id" json:"id"`
	UserID         *string    `db:"user_id" json:"user_id,omitempty"`
	OrganizationID string     `db:"organization_id" json:"organization_id"`
	Name           string     `db:"name" json:"name"`
	Description    *string    `db:"description" json:"description,omitempty"`
	KeyHash        string     `db:"key_hash" json:"-"`
	KeyPrefix      string     `db:"key_prefix" json:"key_prefix"`
	Scopes         []string   `json:"scopes"`
	ExpiresAt      *time.Time `db:"expires_at" json:"expires_at,omitempty"`
	LastUsedAt     *time.Time `db:"last_used_at" json:"last_used_at,omitempty"`
	IsActive       bool       `db:"is_active" json:"is_active"`
	CreatedAt      time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt      time.Time  `db:"updated_at" json:"updated_at"`
}
