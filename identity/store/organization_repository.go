// organization_repository.go implements OrganizationRepository, providing database queries
// for organization CRUD, membership management, and role lookup.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity/auth"
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
// Returns an error wrapping ErrNotFound when no organization is named
// "default"; that result is never cached.
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

	// ErrNotFound propagates: a deployment with no "default" organization is a
	// misconfiguration the caller must see, not an empty value it should try to
	// use. Nothing is cached on that path either — caching a miss would pin the
	// misconfiguration for a further TTL after it was fixed.
	// UNSCOPED BY DESIGN — bootstrap. Resolving the default organization happens
	// before any principal is known (it is what single-tenant deployments resolve
	// every request against), so there is no scope to derive. The platform-wide
	// scope is named explicitly here rather than reached by omission.
	org, err := r.GetByName(ctx, "default", OrgScopeAllOrganizations())
	if err != nil {
		return nil, err
	}
	r.defaultOrgMu.Lock()
	if r.defaultOrgGen == gen {
		// Cache a private copy; org itself is freshly scanned per call and
		// belongs to the caller.
		r.defaultOrgCache = cloneOrganization(org)
		r.defaultOrgAt = time.Now()
	}
	r.defaultOrgMu.Unlock()
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

// GetByName retrieves an organization by its name, within scope.
//
// Returns an error wrapping ErrNotFound when no organization has that name
// inside the scope — the same error an absent organization produces, so the
// name axis is not an existence oracle over other tenants' organization names.
func (r *OrganizationRepository) GetByName(ctx context.Context, name string, scope OrgScope) (*models.Organization, error) {
	if scope.MatchesNothing() {
		return nil, notFound("organization by name")
	}

	// GUARD org-scope-organization-byid (issue #138).
	query := `
		SELECT id, name, display_name, idp_type, idp_name, created_at, updated_at
		FROM organizations
		WHERE name = $1
	`
	args := []interface{}{name}
	query, args = andScope(query, scope, "id", args)

	org := &models.Organization{}
	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&org.ID,
		&org.Name,
		&org.DisplayName,
		&org.IdpType,
		&org.IdpName,
		&org.CreatedAt,
		&org.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, notFound("organization by name")
		}
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	return org, nil
}

// GetByID retrieves an organization by ID, within scope.
//
// Returns an error wrapping ErrNotFound when no organization has that ID inside
// the scope. On this table the row IS the tenant, so the predicate constrains
// the primary key: `id = $1 AND id = ANY($2)`. That reads redundantly and is
// not — $1 is the caller-supplied path parameter and $2 is the caller's
// authority, and keeping them as separate conjuncts is what makes the second
// one impossible to omit when a new access axis is added.
func (r *OrganizationRepository) GetByID(ctx context.Context, id string, scope OrgScope) (*models.Organization, error) {
	if scope.MatchesNothing() {
		return nil, notFound("organization by id")
	}

	// GUARD org-scope-organization-byid (issue #138).
	query := `
		SELECT id, name, display_name, idp_type, idp_name, created_at, updated_at
		FROM organizations
		WHERE id = $1
	`
	args := []interface{}{id}
	query, args = andScope(query, scope, "id", args)

	org := &models.Organization{}
	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&org.ID,
		&org.Name,
		&org.DisplayName,
		&org.IdpType,
		&org.IdpName,
		&org.CreatedAt,
		&org.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, notFound("organization by id")
		}
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	return org, nil
}

// Create creates a new organization, filling org.ID/CreatedAt/UpdatedAt from
// the row the database returns.
//
// UNSCOPED BY DESIGN — this is the one create axis in the package with no
// owning organization to check against, because the row being created IS the
// organization. Authority for it is the platform-tier
// auth.ScopeOrganizationsCreate, which is deliberately not implied by
// organizations:write, and which a consumer enforces on the route.
//
// This is the canonical name for the operation. Until v0.25.0 the same insert
// was reachable as both Create and CreateOrganization; the short name survives
// because every sibling organization-entity operation on this repository —
// GetByID, GetByName, Update, Rename, Delete, List, Count, Search — is
// short-named, so keeping CreateOrganization would have left the receiver with
// one entity-suffixed outlier.
func (r *OrganizationRepository) Create(ctx context.Context, org *models.Organization) error {
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

// AddMemberWithRoleTemplate adds a user to an organization within scope, with
// the specified role template, stamping created_at from the DATABASE clock
// (NOW()).
//
// This is the canonical add-member operation. A second exported name for it,
// AddMember(*models.OrganizationMember), was removed in v0.25.0. The two were
// NOT equivalent: AddMember inserted member.CreatedAt verbatim, so a caller that
// built the struct without setting that field wrote a membership dated
// 0001-01-01 — a silently wrong audit timestamp on a privilege grant, produced
// by the zero value rather than by any explicit decision. Collapsing onto this
// signature makes the server clock the only source of a membership's creation
// time.
func (r *OrganizationRepository) AddMemberWithRoleTemplate(ctx context.Context, orgID, userID string, roleTemplateID *string, scope OrgScope) error {
	if scope.MatchesNothing() {
		return notFound("organization by id")
	}

	// GUARD org-scope-membership-create (issue #138). As on CreateAPIKey, the
	// create axis has no existing row to filter, so the INSERT sources from a
	// scoped SELECT over the target organization: granting membership of an
	// organization outside the scope inserts nothing and reports ErrNotFound.
	// Adding a member is a privilege GRANT, so leaving this axis unscoped while
	// scoping the update and delete axes beside it would leave the strongest of
	// the three open.
	query := `
		INSERT INTO organization_members (organization_id, user_id, role_template_id, created_at)
		SELECT o.id, $2, $3, NOW()
		FROM organizations o
		WHERE o.id = $1
	`
	args := []interface{}{orgID, userID, roleTemplateID}
	query, args = andScope(query, scope, "o.id", args)

	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}

	return requireRow(res, "organization by id")
}

// rowQuerier is the single-row read both a *sql.DB and a *sql.Tx satisfy.
//
// It exists so lookupRoleTemplateID can be reached from inside a transaction
// (Reducer.UpdateMemberRole) and from the pool (AddMemberWithParams) without a
// second copy of the statement.
type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// lookupRoleTemplateID resolves a role template's ID by name, shared by
// AddMemberWithParams, UpdateMemberRole and Reducer.UpdateMemberRole. Returns an
// error when the name does not resolve, rather than a silent NULL role —
// callers that intend no role should use AddMemberWithRoleTemplate(nil) /
// UpdateMemberRoleTemplate(nil).
func lookupRoleTemplateID(ctx context.Context, q rowQuerier, roleTemplateName string) (*string, error) {
	query := `SELECT id FROM role_templates WHERE name = $1`
	var id string
	err := q.QueryRowContext(ctx, query, roleTemplateName).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("role template %q not found", roleTemplateName)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to look up role template: %w", err)
	}
	return &id, nil
}

// AddMemberWithParams adds a user to an organization with the specified role template (by template name)
// This is a convenience method that looks up the role template by name
func (r *OrganizationRepository) AddMemberWithParams(ctx context.Context, orgID, userID, roleTemplateName string, scope OrgScope) error {
	id, err := lookupRoleTemplateID(ctx, r.db, roleTemplateName)
	if err != nil {
		return err
	}
	return r.AddMemberWithRoleTemplate(ctx, orgID, userID, id, scope)
}

// RemoveMember removes a user from an organization, within scope.
//
// Returns an error wrapping ErrNotFound when that user is not a member of that
// organization, so "member removed" cannot be reported for a no-op.
func (r *OrganizationRepository) RemoveMember(ctx context.Context, orgID, userID string, scope OrgScope) error {
	if scope.MatchesNothing() {
		return notFound("organization member")
	}

	// GUARD org-scope-membership-delete (issues #138, #162).
	query := `DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2`
	args := []interface{}{orgID, userID}
	query, args = andScope(query, scope, "organization_id", args)

	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}

	return requireRow(res, "organization member")
}

// UpdateMemberRoleTemplate changes a user's role template in an organization,
// within scope.
//
// Returns an error wrapping ErrNotFound when that user is not a member of that
// organization. A privilege change reported as applied when it matched no row
// is the same defect as a revocation that revokes nothing.
//
// This is the canonical name. UpdateMember(*models.OrganizationMember), which
// delegated here, was removed in v0.25.0: it accepted a whole membership struct
// but wrote only RoleTemplateID, so its name promised more than it did.
func (r *OrganizationRepository) UpdateMemberRoleTemplate(ctx context.Context, orgID, userID string, roleTemplateID *string, scope OrgScope) error {
	if scope.MatchesNothing() {
		return notFound("organization member")
	}

	// GUARD org-scope-membership-update (issue #138).
	query := `
		UPDATE organization_members
		SET role_template_id = $3
		WHERE organization_id = $1 AND user_id = $2
	`
	args := []interface{}{orgID, userID, roleTemplateID}
	query, args = andScope(query, scope, "organization_id", args)

	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update member role template: %w", err)
	}

	return requireRow(res, "organization member")
}

// UpdateMemberRole changes a user's role template in an organization (by template name)
// This is a convenience method that looks up the role template by name
func (r *OrganizationRepository) UpdateMemberRole(ctx context.Context, orgID, userID, roleTemplateName string, scope OrgScope) error {
	id, err := lookupRoleTemplateID(ctx, r.db, roleTemplateName)
	if err != nil {
		return err
	}
	return r.UpdateMemberRoleTemplate(ctx, orgID, userID, id, scope)
}

// GetMember retrieves a user's membership in an organization, within scope.
//
// Returns an error wrapping ErrNotFound when that user is not a member. A
// caller that only wants a yes/no answer should use CheckMembership, which
// absorbs the sentinel into its boolean.
func (r *OrganizationRepository) GetMember(ctx context.Context, orgID, userID string, scope OrgScope) (*models.OrganizationMember, error) {
	if scope.MatchesNothing() {
		return nil, notFound("organization member")
	}

	// GUARD org-scope-membership-byid (issues #138, #161).
	query := `
		SELECT organization_id, user_id, role_template_id, created_at
		FROM organization_members
		WHERE organization_id = $1 AND user_id = $2
	`
	args := []interface{}{orgID, userID}
	query, args = andScope(query, scope, "organization_id", args)

	member := &models.OrganizationMember{}
	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&member.OrganizationID,
		&member.UserID,
		&member.RoleTemplateID,
		&member.CreatedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound("organization member")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get member: %w", err)
	}

	return member, nil
}

// ListMembers retrieves the members of an organization, within scope.
func (r *OrganizationRepository) ListMembers(ctx context.Context, orgID string, scope OrgScope) ([]*models.OrganizationMember, error) {
	if scope.MatchesNothing() {
		return []*models.OrganizationMember{}, nil
	}

	// GUARD org-scope-membership-list (issues #138, #161).
	query := `
		SELECT organization_id, user_id, role_template_id, created_at
		FROM organization_members
		WHERE organization_id = $1
	`
	args := []interface{}{orgID}
	query, args = andScope(query, scope, "organization_id", args)
	query += ` ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, args...)
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

// GetUserOrganizations retrieves the organizations a user belongs to that are
// inside scope.
//
// This is #161. Unscoped, it returned a user's COMPLETE organization list, and
// terraform-registry exposes it at GET /api/v1/users/:id behind the flat
// users:read scope — a scope the per-organization user_manager and org_owner
// role templates grant, and which the session JWT carries org-lessly (#652). So
// a role holder in organization A could read the organizations/
// organization_members rows of organizations they belong to nowhere, on a
// resource whose owning organization is exactly what is being disclosed.
//
// The predicate constrains om.organization_id, not o.id: a membership the
// caller may not see must not appear even when the organization itself is one
// the caller knows about. Filtering on the organization would answer "which of
// MY organizations exist" instead of "which of this user's memberships may I
// see".
//
// This is the canonical name; the ListUserOrganizations alias was removed in
// v0.25.0. "Get" matches this repository's other user-axis accessors
// (GetUserMemberships, GetUserCombinedScopes, GetUserScopesForOrg), where
// "List" is reserved for the organization-axis pagination (List, ListMembers).
func (r *OrganizationRepository) GetUserOrganizations(ctx context.Context, userID string, scope OrgScope) ([]*models.Organization, error) {
	if scope.MatchesNothing() {
		return []*models.Organization{}, nil
	}

	// GUARD org-scope-membership-list (issue #161).
	query := `
		SELECT o.id, o.name, o.display_name, o.idp_type, o.idp_name, o.created_at, o.updated_at
		FROM organizations o
		INNER JOIN organization_members om ON o.id = om.organization_id
		WHERE om.user_id = $1
	`
	args := []interface{}{userID}
	query, args = andScope(query, scope, "om.organization_id", args)
	query += ` ORDER BY o.created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, args...)
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

// CheckMembership checks if a user is a member of an organization within scope
// and returns their role template ID.
//
// A membership outside the scope reports (false, nil, nil) — the same answer as
// no membership at all. That is deliberate: the boolean is consumed as an
// authorization answer, and "not visible to you" and "not a member" must reach
// the same decision or the predicate becomes an oracle.
//
// This is one of the two accessors that deliberately ABSORB ErrNotFound: its
// boolean already carries "not a member" in band, so surfacing the sentinel as
// well would give a caller two ways to spell the same answer and invite it to
// handle only one. Every other error still propagates — a lookup that FAILED
// must not be reported as "not a member", which would be a fail-open for any
// caller reading only the boolean.
func (r *OrganizationRepository) CheckMembership(ctx context.Context, orgID, userID string, scope OrgScope) (bool, *string, error) {
	member, err := r.GetMember(ctx, orgID, userID, scope)
	if errors.Is(err, ErrNotFound) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}

	return true, member.RoleTemplateID, nil
}

// GetMemberWithRole retrieves a user's membership in an organization with role
// template info, within scope.
//
// Returns an error wrapping ErrNotFound when that user is not a member inside
// the scope. This is the accessor both consumers' per-resource route guards are
// built on, so it is also the one most often called with
// OrgScopeAllOrganizations(): a guard deciding "may this caller act in this
// organization" is DERIVING authority and cannot be gated on the authority it
// is deriving.
func (r *OrganizationRepository) GetMemberWithRole(ctx context.Context, orgID, userID string, scope OrgScope) (*models.OrganizationMemberWithUser, error) {
	if scope.MatchesNothing() {
		return nil, notFound("organization member")
	}

	// GUARD org-scope-membership-byid (issues #138, #161).
	// See membership.go for the shared query constant and scan helper. The helper
	// returns the Scan error unwrapped so the sql.ErrNoRows check below still works.
	query, args := andScope(orgMemberByOrgAndUserQuery, scope, "om.organization_id", []interface{}{orgID, userID})
	member, scopesJSON, err := scanOrgMemberWithUser(r.db.QueryRowContext(ctx, query, args...))

	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound("organization member")
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

// Update updates an organization, within scope.
//
// Returns an error wrapping ErrNotFound when no organization has org.ID inside
// the scope. It also rewrites idp_type/idp_name — the organization's identity
// provider binding — so an unscoped update was a cross-tenant authentication
// change, not merely a cosmetic one. The
// default-org cache is invalidated either way: the invalidation is cheap and
// skipping it on the error path would leave a stale entry behind on exactly the
// call whose outcome is least certain.
func (r *OrganizationRepository) Update(ctx context.Context, org *models.Organization, scope OrgScope) error {
	if scope.MatchesNothing() {
		return notFound("organization by id")
	}

	// GUARD org-scope-organization-update (issue #138).
	query := `
		UPDATE organizations
		SET display_name = $2, idp_type = $3, idp_name = $4, updated_at = NOW()
		WHERE id = $1
	`
	args := []interface{}{org.ID, org.DisplayName, org.IdpType, org.IdpName}
	query, args = andScope(query, scope, "id", args)

	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update organization: %w", err)
	}

	r.InvalidateDefaultOrgCache()
	return requireRow(res, "organization by id")
}

// Rename renames an organization (the identity row only), within scope, and
// invalidates the default-org cache. Returns an error wrapping ErrNotFound when
// no organization has that ID inside the scope — a consuming app that cascades the new name into its own
// denormalized tables must not do so on the strength of a rename that renamed
// nothing. Apps that store the organization name denormalized in their
// own domain tables (e.g. the registry's module/provider namespaces) are
// responsible for cascading the new name on their side.
func (r *OrganizationRepository) Rename(ctx context.Context, orgID, newName string, scope OrgScope) error {
	if scope.MatchesNothing() {
		return notFound("organization by id")
	}

	// GUARD org-scope-organization-update (issue #138).
	query := `UPDATE organizations SET name = $1, updated_at = NOW() WHERE id = $2`
	args := []interface{}{newName, orgID}
	query, args = andScope(query, scope, "id", args)

	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("rename organization: %w", err)
	}

	r.InvalidateDefaultOrgCache()
	return requireRow(res, "organization by id")
}

// Delete deletes an organization, within scope.
//
// Returns an error wrapping ErrNotFound when no organization has that ID inside
// the scope. This cascades to the organization's memberships and API keys, so
// it is the highest-blast-radius axis on the table.
func (r *OrganizationRepository) Delete(ctx context.Context, orgID string, scope OrgScope) error {
	if scope.MatchesNothing() {
		return notFound("organization by id")
	}

	// GUARD org-scope-organization-delete (issue #138).
	query := `DELETE FROM organizations WHERE id = $1`
	args := []interface{}{orgID}
	query, args = andScope(query, scope, "id", args)

	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to delete organization: %w", err)
	}

	r.InvalidateDefaultOrgCache()
	return requireRow(res, "organization by id")
}

// List retrieves a paginated list of the organizations inside scope.
func (r *OrganizationRepository) List(ctx context.Context, limit, offset int, scope OrgScope) ([]*models.Organization, error) {
	if scope.MatchesNothing() {
		return []*models.Organization{}, nil
	}

	// GUARD org-scope-organization-list (issue #138): the tenant predicate is
	// applied before LIMIT/OFFSET, so pagination pages the caller's own
	// organizations rather than paging through everyone's.
	query := `
		SELECT id, name, display_name, idp_type, idp_name, created_at, updated_at
		FROM organizations
		WHERE 1=1
	`
	var args []interface{}
	query, args = andScope(query, scope, "id", args)
	query += fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2) // #nosec G202 -- the appended text is a fixed template; its only interpolations are the integer placeholder indices computed from len(args). Every value travels as a query argument.
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
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

// Count returns how many organizations are inside scope.
//
// It is scoped for the same reason List is: a total that counts rows the caller
// cannot see turns the paginated list into a disclosure of how many tenants
// exist, and drives a consumer's page controls off a number its own list can
// never reach.
func (r *OrganizationRepository) Count(ctx context.Context, scope OrgScope) (int, error) {
	if scope.MatchesNothing() {
		return 0, nil
	}

	// GUARD org-scope-organization-list (issue #138).
	var count int
	query := `SELECT COUNT(*) FROM organizations WHERE 1=1`
	var args []interface{}
	query, args = andScope(query, scope, "id", args)

	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count organizations: %w", err)
	}

	return count, nil
}

// Search searches the organizations inside scope by name or display name.
//
// The scope predicate is applied as its own conjunct AFTER the parenthesised
// ILIKE alternation, so no search term can escape it. An OR-ed filter beside an
// AND-ed one is the classic way a tenant predicate gets lost, which is why the
// alternation is parenthesised here rather than left to operator precedence.
func (r *OrganizationRepository) Search(ctx context.Context, query string, limit, offset int, scope OrgScope) ([]*models.Organization, error) {
	if scope.MatchesNothing() {
		return []*models.Organization{}, nil
	}

	// GUARD org-scope-organization-list (issue #138).
	searchQuery := `
		SELECT id, name, display_name, idp_type, idp_name, created_at, updated_at
		FROM organizations
		WHERE (name ILIKE $1 OR display_name ILIKE $1)
	`
	searchPattern := "%" + escapeLikePattern(query) + "%"
	args := []interface{}{searchPattern}
	searchQuery, args = andScope(searchQuery, scope, "id", args)
	searchQuery += fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2) // #nosec G202 -- the appended text is a fixed template; its only interpolations are the integer placeholder indices computed from len(args). Every value travels as a query argument.
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, searchQuery, args...)
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

// ListMembersWithUsers retrieves the members of an organization, within scope,
// with user details and role template info.
func (r *OrganizationRepository) ListMembersWithUsers(ctx context.Context, orgID string, scope OrgScope) ([]*models.OrganizationMemberWithUser, error) {
	if scope.MatchesNothing() {
		return []*models.OrganizationMemberWithUser{}, nil
	}

	// GUARD org-scope-membership-list (issues #138, #161).
	// See membership.go for the shared query constant and scan helper.
	query, args := andScope(orgMembersByOrgQuery, scope, "om.organization_id", []interface{}{orgID})
	rows, err := r.db.QueryContext(ctx, query+orgMembersByOrgOrderBy, args...)
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

// GetUserMemberships retrieves all organization memberships for a user with
// role template info.
//
// UNSCOPED BY DESIGN — authority derivation. This is the accessor OrgScopeForUser
// itself reads, and both consumers' resolvers read, to work out WHICH
// organizations a principal may act in. Requiring a scope here would be
// circular: the caller would have to supply the answer it is asking for.
//
// It is therefore the one accessor on this repository that a consumer must
// still guard for itself when it is asking about SOMEONE ELSE. The right guard
// is not a scope parameter but a different accessor: a consumer showing one
// user's memberships to another user wants GetUserOrganizations (scoped, #161)
// or a scoped ListMembersWithUsers, not this.
func (r *OrganizationRepository) GetUserMemberships(ctx context.Context, userID string) ([]*models.UserMembership, error) {
	// Same shape (and, before membership.go, byte-identical SQL) as
	// UserRepository.GetUserWithOrgRoles; the two differ only in whether they
	// return a value slice or a pointer slice.
	rows, err := r.db.QueryContext(ctx, userMembershipByUserQuery+userMembershipOrderBy, userID)
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
// The return type is auth.GlobalScopes rather than []string, which is what
// enforces the paragraph above rather than merely stating it:
// auth.TokenManager.GenerateForOrg takes auth.OrgScopes, so this cross-org union
// cannot reach an org-BOUND token — the token shape HasScopeInOrg trusts — without
// an explicit auth.OrgScopes(...) conversion that is greppable and reviewable.
// This accessor is NOT marked deprecated: it is the only accessor for the
// suite-wide union, both consumers use it deliberately, and a deprecation
// marker on a method with no replacement is a warning rather than a remedy.
func (r *OrganizationRepository) GetUserCombinedScopes(ctx context.Context, userID string) (auth.GlobalScopes, error) {
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
	scopes := make(auth.GlobalScopes, 0, len(scopeMap))
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
// error. This is the second of the two accessors that deliberately ABSORB
// ErrNotFound: an empty scope set already denies everything, so "not a member"
// and "a member with no scopes" reach the same authorization decision and do not
// need to be distinguished by the caller. A lookup that FAILED still returns its
// error rather than an empty set, so a database fault cannot be mistaken for a
// principal with no permissions and then papered over by a caller that ignores
// errors.
//
// Use this (or models.UserWithOrgRoles.GetScopesForOrg) whenever an authorization decision is
// scoped to a specific organization — pair the result with
// auth.TokenManager.GenerateForOrg to mint the token and auth.HasScopeInOrg /
// auth.HasAnyScopeInOrg / auth.HasAllScopesInOrg to check it, so the org binding
// is enforceable from the token itself. See the doc on GetUserCombinedScopes for
// why that global accessor must not be used for this purpose.
//
// The return type is auth.OrgScopes, the type auth.TokenManager.GenerateForOrg
// accepts, so the org-scoped path type-checks end to end while the
// cross-organization union (auth.GlobalScopes) does not.
func (r *OrganizationRepository) GetUserScopesForOrg(ctx context.Context, userID, orgID string) (auth.OrgScopes, error) {
	// UNSCOPED BY DESIGN — authority derivation, like GetUserMemberships: this
	// computes what the principal may do in orgID, so it cannot be gated on a
	// scope derived from what the principal may do.
	member, err := r.GetMemberWithRole(ctx, orgID, userID, OrgScopeAllOrganizations())
	if errors.Is(err, ErrNotFound) {
		return auth.OrgScopes{}, nil
	}
	if err != nil {
		return nil, err
	}

	// Deduplicate defensively, mirroring GetUserCombinedScopes, in case the role template's
	// scopes ever contain duplicates.
	scopeMap := make(map[string]bool, len(member.RoleTemplateScopes))
	for _, scope := range member.RoleTemplateScopes {
		scopeMap[scope] = true
	}

	scopes := make(auth.OrgScopes, 0, len(scopeMap))
	for scope := range scopeMap {
		scopes = append(scopes, scope)
	}

	return scopes, nil
}

// RemoveAllMembershipsForUser removes a user from every organization INSIDE
// scope and returns, as an OrgScope, the organizations whose membership it
// actually removed.
//
// Used by SCIM deprovisioning. Before v0.25.0 it took no scope and deleted the
// target's rows in every organization, so terraform-state-manager's
// DELETE /scim/v2/Users/:id — gated on the flat scim:provision scope that a
// SINGLE organization's admin role template yields — stripped memberships in
// organizations the caller had no relationship with (#162). The registry had
// already grown a hand-rolled guard for the same axis (its #719); this makes
// the unscoped call unrepresentable instead of merely discouraged, so the two
// consumers cannot drift apart again.
//
// # Why it returns a scope and not a count
//
// The count answered "did the deprovisioning do something"; the SET answers the
// question the next statement in the same request has to ask. Deprovisioning
// also has to revoke the credentials the removed memberships backed, and
// narrowing that sweep is #160 — which must not re-strand credentials
// (#732/#736). Returning the removed organizations AS AN OrgScope makes them
// directly passable to APIKeyRepository.RevokeAPIKeysForUser, so the sweep
// covers exactly the organizations where authority was actually withdrawn:
//
//	removed, err := orgRepo.RemoveAllMembershipsForUser(ctx, userID, scope)
//	...
//	n, err := keyRepo.RevokeAPIKeysForUser(ctx, userID, removed)
//
// A caller that wants the old count reads len(removed.OrganizationIDs()); a
// caller that wants to log which organizations were touched now can, which the
// count never allowed.
//
// Bulk, so removing nothing is not an error: deprovisioning a user who belonged
// to no organization in scope is a legitimate no-op, and the empty scope it
// returns denies the downstream sweep — which is the correct outcome, since no
// authority was reduced anywhere.
func (r *OrganizationRepository) RemoveAllMembershipsForUser(ctx context.Context, userID string, scope OrgScope) (OrgScope, error) {
	if scope.MatchesNothing() {
		return OrgScope{}, nil
	}

	// GUARD org-scope-membership-sweep (issues #160, #162).
	query := `DELETE FROM organization_members WHERE user_id = $1`
	args := []interface{}{userID}
	query, args = andScope(query, scope, "organization_id", args)
	query += ` RETURNING organization_id`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return OrgScope{}, fmt.Errorf("failed to remove all memberships for user %s: %w", userID, err)
	}
	defer rows.Close()

	removed := make([]string, 0)
	for rows.Next() {
		var orgID string
		if err := rows.Scan(&orgID); err != nil {
			return OrgScope{}, fmt.Errorf("failed to scan removed membership for user %s: %w", userID, err)
		}
		removed = append(removed, orgID)
	}
	if err := rows.Err(); err != nil {
		return OrgScope{}, fmt.Errorf("failed to remove all memberships for user %s: %w", userID, err)
	}
	return OrgScopeOrganizations(removed...), nil
}
