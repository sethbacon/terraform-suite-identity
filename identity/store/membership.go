package store

import (
	"encoding/json"
	"fmt"

	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// This file holds the single canonical definition of the two organization-membership
// reads that the repositories share, mirroring the scanAPIKey/rowScanner pattern
// already used for api_keys in api_key_repository.go.
//
// Before this file existed, the same JOIN + column list + Scan-and-unmarshal block
// was hand-copied across five methods on two repository types, so a schema change to
// organization_members or role_templates had to be re-applied (and independently
// re-verified) in five places. There are exactly two shapes:
//
//   - "user membership": which organizations does this user belong to, and with what
//     role template — joins organizations, scans models.UserMembership.
//   - "org member with user": who belongs to this organization, and who are they —
//     joins users, scans models.OrganizationMemberWithUser.
//
// Each shape has one column list, one FROM/JOIN chain, and one scan helper. A future
// change that has to thread a new predicate (e.g. a required tenancy parameter)
// through every membership accessor therefore edits one query constant per shape
// instead of five hand-copied literals.

// ---------------------------------------------------------------------------
// Shape 1: user membership (organization_members ⋈ organizations ⋈ role_templates)
// ---------------------------------------------------------------------------

// userMembershipColumns is the canonical projection scanned by
// scanUserMembership. Keep the two in lockstep: the Scan destination order in
// scanUserMembership is positional and mirrors this list exactly.
const userMembershipColumns = `om.organization_id, COALESCE(o.name, '') as organization_name,
		       om.role_template_id, om.created_at,
		       rt.name as role_template_name, rt.display_name as role_template_display_name,
		       COALESCE(rt.scopes, '[]'::jsonb) as role_template_scopes`

// userMembershipFrom is the canonical FROM/JOIN chain for the user-membership
// shape. Both joins are LEFT so a membership row survives a missing organization
// or a NULL role_template_id (the COALESCEs above supply the defaults).
const userMembershipFrom = `
		FROM organization_members om
		LEFT JOIN organizations o ON om.organization_id = o.id
		LEFT JOIN role_templates rt ON om.role_template_id = rt.id`

// userMembershipByUserQuery reads one user's memberships.
// Used by UserRepository.GetUserWithOrgRoles and
// OrganizationRepository.GetUserMemberships, which issued byte-identical SQL
// before this constant existed and differ only in the slice type they return.
const userMembershipByUserQuery = `
		SELECT ` + userMembershipColumns + userMembershipFrom + `
		WHERE om.user_id = $1
		ORDER BY om.created_at DESC
	`

// userMembershipByUserIDsQuery is the bulk form: it reads memberships for many
// users in one round trip (avoiding N+1) and therefore carries one extra leading
// column, om.user_id, so each row can be attached back to the right user. The
// ORDER BY groups by user first, preserving the created_at DESC ordering that
// userMembershipByUserQuery gives within each user.
const userMembershipByUserIDsQuery = `
		SELECT om.user_id, ` + userMembershipColumns + userMembershipFrom + `
		WHERE om.user_id = ANY($1)
		ORDER BY om.user_id, om.created_at DESC
	`

// unmarshalRoleTemplateScopes decodes the role_template_scopes JSONB column into
// dest. Both membership shapes select that column identically and both wrapped
// a decode failure with exactly this message, so it is shared.
//
// A zero-length value leaves dest untouched (nil) rather than erroring: the
// projections COALESCE to '[]'::jsonb, so an empty byte slice only arises from a
// driver that reports SQL NULL as a zero-length []byte.
func unmarshalRoleTemplateScopes(scopesJSON []byte, dest *[]string) error {
	if len(scopesJSON) == 0 {
		return nil
	}
	if err := json.Unmarshal(scopesJSON, dest); err != nil {
		return fmt.Errorf("failed to parse scopes: %w", err)
	}
	return nil
}

// scanUserMembership scans one userMembershipColumns row into m, including the
// role_template_scopes JSONB unmarshal.
//
// leading holds Scan destinations for any columns selected BEFORE the shared
// projection — only userMembershipByUserIDsQuery uses it, to recover om.user_id.
//
// Unlike scanOrgMemberWithUser this helper wraps the Scan error itself and folds
// in the scopes unmarshal, because all three call sites already produced exactly
// these two messages and none of them inspects the error (there is no single-row
// sql.ErrNoRows caller for this shape).
func scanUserMembership(row rowScanner, m *models.UserMembership, leading ...interface{}) error {
	var scopesJSON []byte
	dest := make([]interface{}, 0, len(leading)+7)
	dest = append(dest, leading...)
	dest = append(dest,
		&m.OrganizationID,
		&m.OrganizationName,
		&m.RoleTemplateID,
		&m.CreatedAt,
		&m.RoleTemplateName,
		&m.RoleTemplateDisplayName,
		&scopesJSON,
	)
	if err := row.Scan(dest...); err != nil {
		return fmt.Errorf("failed to scan membership: %w", err)
	}
	return unmarshalRoleTemplateScopes(scopesJSON, &m.RoleTemplateScopes)
}

// ---------------------------------------------------------------------------
// Shape 2: org member with user (organization_members ⋈ users ⋈ role_templates)
// ---------------------------------------------------------------------------

// orgMemberWithUserColumns is the canonical projection scanned by
// scanOrgMemberWithUser. Keep the two in lockstep: the Scan destination order in
// scanOrgMemberWithUser is positional and mirrors this list exactly.
const orgMemberWithUserColumns = `om.organization_id, om.user_id, om.role_template_id, om.created_at,
		       COALESCE(u.name, '') as user_name, COALESCE(u.email, '') as user_email,
		       rt.name as role_template_name, rt.display_name as role_template_display_name,
		       COALESCE(rt.scopes, '[]'::jsonb) as role_template_scopes`

// orgMemberWithUserFrom is the canonical FROM/JOIN chain for the
// org-member-with-user shape.
const orgMemberWithUserFrom = `
		FROM organization_members om
		LEFT JOIN users u ON om.user_id = u.id
		LEFT JOIN role_templates rt ON om.role_template_id = rt.id`

// orgMemberByOrgAndUserQuery reads a single membership row.
// organization_members enforces UNIQUE(organization_id, user_id), so this
// matches at most one row and is issued with QueryRowContext.
const orgMemberByOrgAndUserQuery = `
		SELECT ` + orgMemberWithUserColumns + orgMemberWithUserFrom + `
		WHERE om.organization_id = $1 AND om.user_id = $2
	`

// orgMembersByOrgQuery reads every membership row for one organization.
const orgMembersByOrgQuery = `
		SELECT ` + orgMemberWithUserColumns + orgMemberWithUserFrom + `
		WHERE om.organization_id = $1
		ORDER BY om.created_at DESC
	`

// scanOrgMemberWithUser scans one orgMemberWithUserColumns row and returns the
// member together with the still-encoded role_template_scopes value, which the
// caller decodes with unmarshalRoleTemplateScopes.
//
// The Scan error is returned UNWRAPPED, exactly as scanAPIKey does and for the
// same reason: the single-row caller (GetMemberWithRole) must still be able to
// test `err == sql.ErrNoRows` to distinguish "no such member" from a real
// failure.
//
// The scopes decode is deliberately left to the caller here rather than folded
// in as it is for scanUserMembership. The two callers wrap a Scan failure with
// DIFFERENT wording ("failed to get member" vs "failed to scan member"), so a
// single combined error return would force one of them to change — and worse,
// GetMemberWithRole's `if err != nil` wrap would then double-wrap an already-
// wrapped parse error into "failed to get member: failed to parse scopes: …".
// Handing back the raw bytes keeps every existing error string byte-identical.
func scanOrgMemberWithUser(row rowScanner) (*models.OrganizationMemberWithUser, []byte, error) {
	member := &models.OrganizationMemberWithUser{}
	var scopesJSON []byte
	if err := row.Scan(
		&member.OrganizationID,
		&member.UserID,
		&member.RoleTemplateID,
		&member.CreatedAt,
		&member.UserName,
		&member.UserEmail,
		&member.RoleTemplateName,
		&member.RoleTemplateDisplayName,
		&scopesJSON,
	); err != nil {
		return nil, nil, err
	}
	return member, scopesJSON, nil
}
