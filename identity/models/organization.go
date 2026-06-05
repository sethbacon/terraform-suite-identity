package models

import "time"

// Organization is an identity organization (tenant) record.
type Organization struct {
	ID          string    `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	DisplayName string    `db:"display_name" json:"display_name"`
	Description *string   `db:"description" json:"description,omitempty"`
	IsActive    bool      `db:"is_active" json:"is_active"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
}

// OrganizationMember links a user to an organization with an optional role template.
type OrganizationMember struct {
	ID             string    `db:"id" json:"id"`
	OrganizationID string    `db:"organization_id" json:"organization_id"`
	UserID         string    `db:"user_id" json:"user_id"`
	RoleTemplateID *string   `db:"role_template_id" json:"role_template_id,omitempty"`
	CreatedAt      time.Time `db:"created_at" json:"created_at"`
	UpdatedAt      time.Time `db:"updated_at" json:"updated_at"`
}

// OrganizationMemberWithRole is a membership joined with the user's profile and
// the role template's name and scopes.
type OrganizationMemberWithRole struct {
	OrganizationMember
	UserEmail          string   `db:"user_email" json:"user_email"`
	UserName           string   `db:"user_name" json:"user_name"`
	RoleTemplateName   *string  `db:"role_template_name" json:"role_template_name,omitempty"`
	RoleTemplateScopes []string `json:"role_template_scopes,omitempty"`
}
