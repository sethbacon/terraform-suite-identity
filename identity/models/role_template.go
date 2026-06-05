package models

import "time"

// RoleTemplate is a named set of RBAC scopes assignable to organization members.
type RoleTemplate struct {
	ID          string    `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	DisplayName string    `db:"display_name" json:"display_name"`
	Description *string   `db:"description" json:"description,omitempty"`
	Scopes      []string  `json:"scopes"`
	IsSystem    bool      `db:"is_system" json:"is_system"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
}
