package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// OrganizationMember represents a user's membership in an organization.
type OrganizationMember struct {
	OrganizationID string
	UserID         string
	RoleTemplateID *string // Reference to role_templates table
	CreatedAt      time.Time
}

// RoleTemplateUUID is a typed convenience accessor equivalent to
// ParseRoleTemplateID(m.RoleTemplateID) — see ParseRoleTemplateID for the
// exact (uuid.UUID, bool, error) semantics. Added so callers that need the
// uuid.UUID RoleTemplateRepository expects have a one-line method instead of
// each hand-rolling their own uuid.Parse against the *string field.
func (m *OrganizationMember) RoleTemplateUUID() (uuid.UUID, bool, error) {
	return ParseRoleTemplateID(m.RoleTemplateID)
}

// ParseRoleTemplateID converts an OrganizationMember-style *string
// RoleTemplateID (also used by OrganizationMemberWithUser and UserMembership)
// into the uuid.UUID that RoleTemplateRepository.GetRoleTemplate and
// RoleTemplateRepository.DeleteRoleTemplate require, so callers that need to
// cross that string/uuid.UUID boundary have one documented place to do it
// instead of each hand-rolling their own uuid.Parse.
//
// A nil id (no role template assigned) returns (uuid.Nil, false, nil) — not an
// error. A non-nil id that fails to parse as a UUID returns a non-nil error.
func ParseRoleTemplateID(id *string) (uuid.UUID, bool, error) {
	if id == nil {
		return uuid.Nil, false, nil
	}
	parsed, err := uuid.Parse(*id)
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("invalid role template id %q: %w", *id, err)
	}
	return parsed, true, nil
}

// OrganizationMemberWithUser includes user details and role template info for display.
type OrganizationMemberWithUser struct {
	OrganizationID          string    `json:"organization_id"`
	UserID                  string    `json:"user_id"`
	RoleTemplateID          *string   `json:"role_template_id"`
	RoleTemplateName        *string   `json:"role_template_name"`
	RoleTemplateDisplayName *string   `json:"role_template_display_name"`
	RoleTemplateScopes      []string  `json:"role_template_scopes"`
	CreatedAt               time.Time `json:"created_at"`
	UserName                string    `json:"user_name"`
	UserEmail               string    `json:"user_email"`
}

// RoleTemplateUUID is the OrganizationMemberWithUser counterpart of
// OrganizationMember.RoleTemplateUUID; see ParseRoleTemplateID.
func (m *OrganizationMemberWithUser) RoleTemplateUUID() (uuid.UUID, bool, error) {
	return ParseRoleTemplateID(m.RoleTemplateID)
}

// UserMembership includes organization details for a user's membership.
type UserMembership struct {
	OrganizationID          string    `json:"organization_id"`
	OrganizationName        string    `json:"organization_name"`
	RoleTemplateID          *string   `json:"role_template_id"`
	RoleTemplateName        *string   `json:"role_template_name"`
	RoleTemplateDisplayName *string   `json:"role_template_display_name"`
	RoleTemplateScopes      []string  `json:"role_template_scopes"`
	CreatedAt               time.Time `json:"created_at"`
}

// RoleTemplateUUID is the UserMembership counterpart of
// OrganizationMember.RoleTemplateUUID; see ParseRoleTemplateID.
func (m *UserMembership) RoleTemplateUUID() (uuid.UUID, bool, error) {
	return ParseRoleTemplateID(m.RoleTemplateID)
}
