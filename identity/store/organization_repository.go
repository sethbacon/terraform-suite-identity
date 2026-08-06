// organization_repository.go implements OrganizationRepository, providing database queries
// for organization CRUD, membership management, and role lookup.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// OrganizationRepository handles database operations for organizations
type OrganizationRepository struct {
	db *sql.DB

	// Cache for GetDefaultOrganization (called on nearly every request).
	//
	// defaultOrgCache is owned exclusively by this repository: nothing outside
	// GetDefaultOrganization/InvalidateDefaultOrgCache ever holds a pointer to
	// it or to anything reachable from it. Both the value stored here and the
	// value handed to a caller are produced by cloneOrganization, so a caller
	// mutating its result cannot reach process-wide state.
	//
	// defaultOrgGen is the invalidation generation. It is bumped by
	// InvalidateDefaultOrgCache and re-checked before a refill commits, so a
	// database read that was already in flight when an invalidation happened
	// cannot write its pre-invalidation result back into the cache.
	defaultOrgMu    sync.RWMutex
	defaultOrgCache *models.Organization
	defaultOrgAt    time.Time
	defaultOrgGen   uint64
}

const defaultOrgCacheTTL = 60 * time.Second

// cloneOrganization returns an organization that shares no mutable state with
// org, so the two can be handed to unrelated owners.
//
// models.Organization's only reference-typed fields are the *string IdpType
// and IdpName, so a one-level deep copy — the struct plus fresh backing
// strings for those two pointers — is exactly the depth required; there is no
// slice, map, or nested struct pointer below them to follow. Strings and
// time.Time are values and need no copying of their own. If a reference-typed
// field is ever added to models.Organization, this function must grow with it
// (TestCloneOrganizationCoversEveryReferenceField enforces that).
func cloneOrganization(org *models.Organization) *models.Organization {
	if org == nil {
		return nil
	}
	cp := *org
	if org.IdpType != nil {
		v := *org.IdpType
		cp.IdpType = &v
	}
	if org.IdpName != nil {
		v := *org.IdpName
		cp.IdpName = &v
	}
	return &cp
}

// NewOrganizationRepository creates a new organization repository
func NewOrganizationRepository(db *sql.DB) *OrganizationRepository {
	return &OrganizationRepository{db: db}
}

// GetDefaultOrganization retrieves the default organization for single-tenant mode.
// Results are cached in memory with a 60-second TTL since the default org rarely changes.
//
// The cache is per-instance: InvalidateDefaultOrgCache (called by Rename/Update/Delete)
// only clears the cache on the OrganizationRepository that performed the write. In a
// horizontally scaled deployment, another replica's cache is unaffected and continues
// returning the pre-change organization for up to defaultOrgCacheTTL after a rename —
// a known, accepted cross-replica staleness window. This is acceptable because the
// default organization's identity (not its display fields) is what matters for
// authorization, and that never changes via Rename/Update. If the default org's
// display fields are ever used for anything beyond display, shorten the TTL or
// replace this cache with a shared invalidation signal (e.g. LISTEN/NOTIFY).
//
// The returned *models.Organization is always the caller's own: on every path
// — cache hit and cache refill alike — it shares no memory with the cached
// entry, so the idiomatic get-mutate-Update pattern
// (org, _ := GetDefaultOrganization(ctx); org.DisplayName = x; Update(ctx, org))
// cannot publish an uncommitted, or never-committed, edit to every other
// caller in the process. Conversely, the cached entry is this repository's own
// copy, so it cannot be reached through any value a caller still holds.
//
// A refill only commits if no invalidation occurred while its database read
// was in flight. Without that check, a read that started before a concurrent
// Rename/Update/Delete could land after InvalidateDefaultOrgCache and
// reinstate the pre-change organization for a further full TTL on the very
// instance whose cache the write had just cleared.
func (r *OrganizationRepository) GetDefaultOrganization(ctx context.Context) (*models.Organization, error) {
	r.defaultOrgMu.RLock()
	if r.defaultOrgCache != nil && time.Since(r.defaultOrgAt) < defaultOrgCacheTTL {
		org := cloneOrganization(r.defaultOrgCache)
		r.defaultOrgMu.RUnlock()
		return org, nil
	}
	// Read the generation under the same critical section that decided this
	// is a miss, so the window being guarded starts no later than the miss.
	gen := r.defaultOrgGen
	r.defaultOrgMu.RUnlock()

	org, err := r.GetByName(ctx, "default")
	if err != nil {
		return nil, err
	}
	if org != nil {
		r.defaultOrgMu.Lock()
		if r.defaultOrgGen == gen {
			// Cache a private copy; org itself is freshly scanned per call and
			// belongs to the caller.
			r.defaultOrgCache = cloneOrganization(org)
			r.defaultOrgAt = time.Now()
		}
		r.defaultOrgMu.Unlock()
	}
	return org, nil
}

// InvalidateDefaultOrgCache clears the cached default organization,
// forcing the next call to GetDefaultOrganization to query the database.
//
// It also bumps the invalidation generation, which discards the result of any
// GetDefaultOrganization refill whose read was already in flight — those
// results predate the write that triggered this call, so caching them would
// undo the invalidation.
func (r *OrganizationRepository) InvalidateDefaultOrgCache() {
	r.defaultOrgMu.Lock()
	r.defaultOrgCache = nil
	r.defaultOrgGen++
	r.defaultOrgMu.Unlock()
}

// GetByName retrieves an organization by its name
func (r *OrganizationRepository) GetByName(ctx context.Context, name string) (*models.Organization, error) {
	query := `
		SELECT id, name, display_name, idp_type, idp_name, created_at, updated_at
		FROM organizations
		WHERE name = $1
	`

	org := &models.Organization{}
	err := r.db.QueryRowContext(ctx, query, name).Scan(
		&org.ID,
		&org.Name,
		&org.DisplayName,
		&org.IdpType,
		&org.IdpName,
		&org.CreatedAt,
		&org.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	return org, nil
}

// GetByID retrieves an organization by ID
func (r *OrganizationRepository) GetByID(ctx context.Context, id string) (*models.Organization, error) {
	query := `
		SELECT id, name, display_name, idp_type, idp_name, created_at, updated_at
		FROM organizations
		WHERE id = $1
	`

	org := &models.Organization{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&org.ID,
		&org.Name,
		&org.DisplayName,
		&org.IdpType,
		&org.IdpName,
		&org.CreatedAt,
		&org.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	return org, nil
}

// CreateOrganization creates a new organization
func (r *OrganizationRepository) CreateOrganization(ctx context.Context, org *models.Organization) error {
	query := `
		INSERT INTO organizations (name, display_name)
		VALUES ($1, $2)
		RETURNING id, created_at, updated_at
	`

	err := r.db.QueryRowContext(ctx, query, org.Name, org.DisplayName).Scan(
		&org.ID,
		&org.CreatedAt,
		&org.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create organization: %w", err)
	}

	r.InvalidateDefaultOrgCache()
	return nil
}

// === Organization Membership Operations ===

// AddMemberWithRoleTemplate adds a user to an organization with the specified role template
func (r *OrganizationRepository) AddMemberWithRoleTemplate(ctx context.Context, orgID, userID string, roleTemplateID *string) error {
	query := `
		INSERT INTO organization_members (organization_id, user_id, role_template_id, created_at)
		VALUES ($1, $2, $3, NOW())
	`

	_, err := r.db.ExecContext(ctx, query, orgID, userID, roleTemplateID)
	if err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}

	return nil
}

// lookupRoleTemplateID resolves a role template's ID by name, shared by
// AddMemberWithParams and UpdateMemberRole. Returns an error when the name
// does not resolve, rather than a silent NULL role — callers that intend no
// role should use AddMemberWithRoleTemplate(nil) / UpdateMemberRoleTemplate(nil).
func (r *OrganizationRepository) lookupRoleTemplateID(ctx context.Context, roleTemplateName string) (*string, error) {
	query := `SELECT id FROM role_templates WHERE name = $1`
	var id string
	err := r.db.QueryRowContext(ctx, query, roleTemplateName).Scan(&id)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("role template %q not found", roleTemplateName)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to look up role template: %w", err)
	}
	return &id, nil
}

// AddMemberWithParams adds a user to an organization with the specified role template (by template name)
// This is a convenience method that looks up the role template by name
func (r *OrganizationRepository) AddMemberWithParams(ctx context.Context, orgID, userID, roleTemplateName string) error {
	id, err := r.lookupRoleTemplateID(ctx, roleTemplateName)
	if err != nil {
		return err
	}
	return r.AddMemberWithRoleTemplate(ctx, orgID, userID, id)
}

// RemoveMember removes a user from an organization
func (r *OrganizationRepository) RemoveMember(ctx context.Context, orgID, userID string) error {
	query := `DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2`
	_, err := r.db.ExecContext(ctx, query, orgID, userID)
	if err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}

	return nil
}

// UpdateMemberRoleTemplate changes a user's role template in an organization
func (r *OrganizationRepository) UpdateMemberRoleTemplate(ctx context.Context, orgID, userID string, roleTemplateID *string) error {
	query := `
		UPDATE organization_members
		SET role_template_id = $3
		WHERE organization_id = $1 AND user_id = $2
	`

	_, err := r.db.ExecContext(ctx, query, orgID, userID, roleTemplateID)
	if err != nil {
		return fmt.Errorf("failed to update member role template: %w", err)
	}

	return nil
}

// UpdateMemberRole changes a user's role template in an organization (by template name)
// This is a convenience method that looks up the role template by name
func (r *OrganizationRepository) UpdateMemberRole(ctx context.Context, orgID, userID, roleTemplateName string) error {
	id, err := r.lookupRoleTemplateID(ctx, roleTemplateName)
	if err != nil {
		return err
	}
	return r.UpdateMemberRoleTemplate(ctx, orgID, userID, id)
}

// GetMember retrieves a user's membership in an organization
func (r *OrganizationRepository) GetMember(ctx context.Context, orgID, userID string) (*models.OrganizationMember, error) {
	query := `
		SELECT organization_id, user_id, role_template_id, created_at
		FROM organization_members
		WHERE organization_id = $1 AND user_id = $2
	`

	member := &models.OrganizationMember{}
	err := r.db.QueryRowContext(ctx, query, orgID, userID).Scan(
		&member.OrganizationID,
		&member.UserID,
		&member.RoleTemplateID,
		&member.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get member: %w", err)
	}

	return member, nil
}

// ListMembers retrieves all members of an organization
func (r *OrganizationRepository) ListMembers(ctx context.Context, orgID string) ([]*models.OrganizationMember, error) {
	query := `
		SELECT organization_id, user_id, role_template_id, created_at
		FROM organization_members
		WHERE organization_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list members: %w", err)
	}
	defer rows.Close()

	members := make([]*models.OrganizationMember, 0)
	for rows.Next() {
		member := &models.OrganizationMember{}
		err := rows.Scan(
			&member.OrganizationID,
			&member.UserID,
			&member.RoleTemplateID,
			&member.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan member: %w", err)
		}
		members = append(members, member)
	}

	return members, rows.Err()
}

// GetUserOrganizations retrieves all organizations a user belongs to
func (r *OrganizationRepository) GetUserOrganizations(ctx context.Context, userID string) ([]*models.Organization, error) {
	query := `
		SELECT o.id, o.name, o.display_name, o.idp_type, o.idp_name, o.created_at, o.updated_at
		FROM organizations o
		INNER JOIN organization_members om ON o.id = om.organization_id
		WHERE om.user_id = $1
		ORDER BY o.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user organizations: %w", err)
	}
	defer rows.Close()

	organizations := make([]*models.Organization, 0)
	for rows.Next() {
		org := &models.Organization{}
		err := rows.Scan(
			&org.ID,
			&org.Name,
			&org.DisplayName,
			&org.IdpType,
			&org.IdpName,
			&org.CreatedAt,
			&org.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan organization: %w", err)
		}
		organizations = append(organizations, org)
	}

	return organizations, rows.Err()
}

// CheckMembership checks if a user is a member of an organization and returns their role template ID
func (r *OrganizationRepository) CheckMembership(ctx context.Context, orgID, userID string) (bool, *string, error) {
	member, err := r.GetMember(ctx, orgID, userID)
	if err != nil {
		return false, nil, err
	}

	if member == nil {
		return false, nil, nil
	}

	return true, member.RoleTemplateID, nil
}

// GetMemberWithRole retrieves a user's membership in an organization with role template info
func (r *OrganizationRepository) GetMemberWithRole(ctx context.Context, orgID, userID string) (*models.OrganizationMemberWithUser, error) {
	// See membership.go for the shared query constant and scan helper. The helper
	// returns the Scan error unwrapped so the sql.ErrNoRows check below still works.
	member, scopesJSON, err := scanOrgMemberWithUser(r.db.QueryRowContext(ctx, orgMemberByOrgAndUserQuery, orgID, userID))

	if err == sql.ErrNoRows {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get member: %w", err)
	}

	// Parse scopes JSON
	if err := unmarshalRoleTemplateScopes(scopesJSON, &member.RoleTemplateScopes); err != nil {
		return nil, err
	}

	return member, nil
}

// Create is an alias for CreateOrganization to match admin handlers
func (r *OrganizationRepository) Create(ctx context.Context, org *models.Organization) error {
	return r.CreateOrganization(ctx, org)
}

// Update updates an organization
func (r *OrganizationRepository) Update(ctx context.Context, org *models.Organization) error {
	query := `
		UPDATE organizations
		SET display_name = $2, idp_type = $3, idp_name = $4, updated_at = NOW()
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, org.ID, org.DisplayName, org.IdpType, org.IdpName)
	if err != nil {
		return fmt.Errorf("failed to update organization: %w", err)
	}

	r.InvalidateDefaultOrgCache()
	return nil
}

// Rename renames an organization (the identity row only) and invalidates the
// default-org cache. Apps that store the organization name denormalized in their
// own domain tables (e.g. the registry's module/provider namespaces) are
// responsible for cascading the new name on their side.
func (r *OrganizationRepository) Rename(ctx context.Context, orgID, newName string) error {
	if _, err := r.db.ExecContext(ctx,
		`UPDATE organizations SET name = $1, updated_at = NOW() WHERE id = $2`,
		newName, orgID,
	); err != nil {
		return fmt.Errorf("rename organization: %w", err)
	}

	r.InvalidateDefaultOrgCache()
	return nil
}

// Delete deletes an organization
func (r *OrganizationRepository) Delete(ctx context.Context, orgID string) error {
	query := `DELETE FROM organizations WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, orgID)
	if err != nil {
		return fmt.Errorf("failed to delete organization: %w", err)
	}

	r.InvalidateDefaultOrgCache()
	return nil
}

// List retrieves a paginated list of organizations
func (r *OrganizationRepository) List(ctx context.Context, limit, offset int) ([]*models.Organization, error) {
	query := `
		SELECT id, name, display_name, idp_type, idp_name, created_at, updated_at
		FROM organizations
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer rows.Close()

	orgs := make([]*models.Organization, 0)
	for rows.Next() {
		org := &models.Organization{}
		err := rows.Scan(
			&org.ID,
			&org.Name,
			&org.DisplayName,
			&org.IdpType,
			&org.IdpName,
			&org.CreatedAt,
			&org.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan organization: %w", err)
		}
		orgs = append(orgs, org)
	}

	return orgs, rows.Err()
}

// Count returns the total number of organizations
func (r *OrganizationRepository) Count(ctx context.Context) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM organizations`
	err := r.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count organizations: %w", err)
	}

	return count, nil
}

// Search searches for organizations by name or display name
func (r *OrganizationRepository) Search(ctx context.Context, query string, limit, offset int) ([]*models.Organization, error) {
	searchQuery := `
		SELECT id, name, display_name, idp_type, idp_name, created_at, updated_at
		FROM organizations
		WHERE name ILIKE $1 OR display_name ILIKE $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	searchPattern := "%" + escapeLikePattern(query) + "%"
	rows, err := r.db.QueryContext(ctx, searchQuery, searchPattern, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to search organizations: %w", err)
	}
	defer rows.Close()

	orgs := make([]*models.Organization, 0)
	for rows.Next() {
		org := &models.Organization{}
		err := rows.Scan(
			&org.ID,
			&org.Name,
			&org.DisplayName,
			&org.IdpType,
			&org.IdpName,
			&org.CreatedAt,
			&org.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan organization: %w", err)
		}
		orgs = append(orgs, org)
	}

	return orgs, rows.Err()
}

// ListUserOrganizations is an alias for GetUserOrganizations
func (r *OrganizationRepository) ListUserOrganizations(ctx context.Context, userID string) ([]*models.Organization, error) {
	return r.GetUserOrganizations(ctx, userID)
}

// AddMember with models.OrganizationMember parameter
func (r *OrganizationRepository) AddMember(ctx context.Context, member *models.OrganizationMember) error {
	query := `
		INSERT INTO organization_members (organization_id, user_id, role_template_id, created_at)
		VALUES ($1, $2, $3, $4)
	`

	_, err := r.db.ExecContext(ctx, query,
		member.OrganizationID,
		member.UserID,
		member.RoleTemplateID,
		member.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}

	return nil
}

// UpdateMember updates a member's information
func (r *OrganizationRepository) UpdateMember(ctx context.Context, member *models.OrganizationMember) error {
	return r.UpdateMemberRoleTemplate(ctx, member.OrganizationID, member.UserID, member.RoleTemplateID)
}

// ListMembersWithUsers retrieves all members of an organization with user details and role template info
func (r *OrganizationRepository) ListMembersWithUsers(ctx context.Context, orgID string) ([]*models.OrganizationMemberWithUser, error) {
	// See membership.go for the shared query constant and scan helper.
	rows, err := r.db.QueryContext(ctx, orgMembersByOrgQuery, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list members with users: %w", err)
	}
	defer rows.Close()

	members := make([]*models.OrganizationMemberWithUser, 0)
	for rows.Next() {
		member, scopesJSON, err := scanOrgMemberWithUser(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan member: %w", err)
		}
		// Parse scopes JSON
		if err := unmarshalRoleTemplateScopes(scopesJSON, &member.RoleTemplateScopes); err != nil {
			return nil, err
		}
		members = append(members, member)
	}

	return members, rows.Err()
}

// GetUserMemberships retrieves all organization memberships for a user with role template info
func (r *OrganizationRepository) GetUserMemberships(ctx context.Context, userID string) ([]*models.UserMembership, error) {
	// Same shape (and, before membership.go, byte-identical SQL) as
	// UserRepository.GetUserWithOrgRoles; the two differ only in whether they
	// return a value slice or a pointer slice.
	rows, err := r.db.QueryContext(ctx, userMembershipByUserQuery, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user memberships: %w", err)
	}
	defer rows.Close()

	memberships := make([]*models.UserMembership, 0)
	for rows.Next() {
		m := &models.UserMembership{}
		if err := scanUserMembership(rows, m); err != nil {
			return nil, err
		}
		memberships = append(memberships, m)
	}

	return memberships, rows.Err()
}

// GetUserCombinedScopes retrieves all unique scopes for a user, unioned across
// ALL of their organization memberships into one flat, GLOBAL set that carries
// NO per-organization qualifier.
//
// Do NOT feed this directly into a JWT (or any other authorization decision) as
// "what the user can do" for a specific organization: a user who is admin in
// one organization and merely a viewer in another gets admin-level scopes in
// this set, because nothing in it distinguishes which organization granted
// which scope — that is exactly the cross-org privilege-escalation primitive
// this accessor must not be used to build. If the decision is scoped to a
// single organization — the common case for any multi-tenant, per-resource
// check — use GetUserScopesForOrg instead, paired with
// auth.TokenManager.GenerateForOrg (to mint the token) and auth.HasScopeInOrg /
// auth.HasAnyScopeInOrg / auth.HasAllScopesInOrg (to check it), so the org
// binding is enforceable from the token itself rather than trusted from a flat
// scope list.
//
// The only legitimate use of this GLOBAL set is a deliberately suite-wide,
// org-independent decision (e.g. a system/superuser scope check that by design
// applies across every organization); it must never stand in for a per-org
// authorization check.
//
// Deprecated: prefer GetUserScopesForOrg for any per-organization authorization
// decision; see the warning above for the narrow legitimate use this is
// retained for.
func (r *OrganizationRepository) GetUserCombinedScopes(ctx context.Context, userID string) ([]string, error) {
	memberships, err := r.GetUserMemberships(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Use a map to deduplicate scopes
	scopeMap := make(map[string]bool)
	for _, m := range memberships {
		for _, scope := range m.RoleTemplateScopes {
			scopeMap[scope] = true
		}
	}

	// Convert map to slice
	scopes := make([]string, 0, len(scopeMap))
	for scope := range scopeMap {
		scopes = append(scopes, scope)
	}

	return scopes, nil
}

// GetUserScopesForOrg retrieves the scopes granted to a user by their role template within a
// SINGLE target organization (orgID), rather than unioning across every organization the user
// belongs to. The organization_members table enforces UNIQUE(organization_id, user_id), so a
// user has at most one membership row — and therefore at most one role template — per
// organization; this returns that membership's deduplicated RoleTemplateScopes.
//
// If the user has no membership in orgID, this returns an empty (non-nil) slice and a nil
// error — mirroring GetMember/GetMemberWithRole's "no rows -> empty result, not error"
// convention in this file, rather than returning sql.ErrNoRows.
//
// Use this (or models.UserWithOrgRoles.GetScopesForOrg) whenever an authorization decision is
// scoped to a specific organization — pair the result with
// auth.TokenManager.GenerateForOrg to mint the token and auth.HasScopeInOrg /
// auth.HasAnyScopeInOrg / auth.HasAllScopesInOrg to check it, so the org binding
// is enforceable from the token itself. See the doc on GetUserCombinedScopes for
// why that global accessor must not be used for this purpose.
func (r *OrganizationRepository) GetUserScopesForOrg(ctx context.Context, userID, orgID string) ([]string, error) {
	member, err := r.GetMemberWithRole(ctx, orgID, userID)
	if err != nil {
		return nil, err
	}
	if member == nil {
		return []string{}, nil
	}

	// Deduplicate defensively, mirroring GetUserCombinedScopes, in case the role template's
	// scopes ever contain duplicates.
	scopeMap := make(map[string]bool, len(member.RoleTemplateScopes))
	for _, scope := range member.RoleTemplateScopes {
		scopeMap[scope] = true
	}

	scopes := make([]string, 0, len(scopeMap))
	for scope := range scopeMap {
		scopes = append(scopes, scope)
	}

	return scopes, nil
}

// RemoveAllMembershipsForUser removes a user from all organizations.
// Used by SCIM deprovisioning to soft-delete/deactivate a user.
func (r *OrganizationRepository) RemoveAllMembershipsForUser(ctx context.Context, userID string) error {
	query := `DELETE FROM organization_members WHERE user_id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to remove all memberships for user %s: %w", userID, err)
	}
	return nil
}
