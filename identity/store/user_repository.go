// Package store implements the data access layer (repository pattern) for the shared identity model.
// Each repository type encapsulates all database queries for a domain entity.
// Handlers never issue SQL directly — all database access goes through this layer, which makes query logic testable in isolation and prevents accidental cross-domain data access.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// UserRepository handles user database operations
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new UserRepository
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

// isUniqueViolation reports whether err is a Postgres unique-constraint
// violation (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505"
}

// CreateUser creates a new user
func (r *UserRepository) CreateUser(ctx context.Context, user *models.User) error {
	user.ID = uuid.New().String()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	query := `
		INSERT INTO users (id, email, name, oidc_sub, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := r.db.ExecContext(ctx, query,
		user.ID,
		user.Email,
		user.Name,
		user.OIDCSub,
		user.CreatedAt,
		user.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetUserByID retrieves a user by ID.
//
// Returns an error wrapping ErrNotFound when no user has that ID.
func (r *UserRepository) GetUserByID(ctx context.Context, userID string) (*models.User, error) {
	query := `
		SELECT id, email, name, oidc_sub, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	user := &models.User{}
	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&user.ID,
		&user.Email,
		&user.Name,
		&user.OIDCSub,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound("user by id")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}

	return user, nil
}

// GetUserByEmail retrieves a user by email.
//
// Returns an error wrapping ErrNotFound when no user has that email.
func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT id, email, name, oidc_sub, created_at, updated_at
		FROM users
		WHERE email = $1
	`

	user := &models.User{}
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Name,
		&user.OIDCSub,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound("user by email")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return user, nil
}

// GetUserByOIDCSub retrieves a user by OIDC subject identifier.
//
// Returns an error wrapping ErrNotFound when no user carries that subject —
// the ordinary result for a first login, which GetOrCreateUserFromOIDC handles.
func (r *UserRepository) GetUserByOIDCSub(ctx context.Context, oidcSub string) (*models.User, error) {
	query := `
		SELECT id, email, name, oidc_sub, created_at, updated_at
		FROM users
		WHERE oidc_sub = $1
	`

	user := &models.User{}
	err := r.db.QueryRowContext(ctx, query, oidcSub).Scan(
		&user.ID,
		&user.Email,
		&user.Name,
		&user.OIDCSub,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound("user by oidc sub")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get user by oidc sub: %w", err)
	}

	return user, nil
}

// UpdateUser updates a user's information.
//
// Returns an error wrapping ErrNotFound when no row has user.ID, so an edit
// applied to a user that was deleted concurrently is not reported as a
// successful save.
func (r *UserRepository) UpdateUser(ctx context.Context, user *models.User) error {
	user.UpdatedAt = time.Now()

	query := `
		UPDATE users
		SET email = $2, name = $3, oidc_sub = $4, updated_at = $5
		WHERE id = $1
	`

	res, err := r.db.ExecContext(ctx, query,
		user.ID,
		user.Email,
		user.Name,
		user.OIDCSub,
		user.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return requireRow(res, "user by id")
}

// linkOIDCIdentity atomically links oidcSub to the pre-provisioned user
// identified by userID, updating email and name to the incoming OIDC values.
// The WHERE clause requires oidc_sub IS NULL, making this a compare-and-set:
// if a concurrent call already linked a (possibly different) oidc_sub to this
// row first, this UPDATE affects zero rows and returns (false, nil) instead of
// overwriting the winner. Returns (true, nil) when this call won the race.
//
// This closes a TOCTOU race in GetOrCreateUserFromOIDC's pre-provisioned-
// account link path: the prior plain UpdateUser call let two concurrent
// logins with the same email but different oidc_sub both "succeed"
// (last-write-wins), since neither the UNIQUE(oidc_sub) constraint nor a
// transaction guarded that path — unlike the brand-new-account INSERT path,
// which already used ON CONFLICT (oidc_sub) DO NOTHING for the same reason.
func (r *UserRepository) linkOIDCIdentity(ctx context.Context, userID, oidcSub, email, name string) (bool, error) {
	query := `
		UPDATE users
		SET email = $2, name = $3, oidc_sub = $4, updated_at = $5
		WHERE id = $1 AND oidc_sub IS NULL
	`

	result, err := r.db.ExecContext(ctx, query, userID, email, name, oidcSub, time.Now())
	if err != nil {
		return false, fmt.Errorf("failed to link oidc identity: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected linking oidc identity: %w", err)
	}
	return n > 0, nil
}

// DeleteUser deletes a user (cascades to API keys and memberships).
//
// Returns an error wrapping ErrNotFound when no row has that ID. Deleting a
// user is a security-state change a consuming app reports to an operator and
// writes to its audit log; a stale or wrong id must not produce a nil error
// that both records as a deletion that never happened.
func (r *UserRepository) DeleteUser(ctx context.Context, userID string) error {
	query := `DELETE FROM users WHERE id = $1`
	res, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return requireRow(res, "user by id")
}

// listUsersPage runs the paginated users SELECT for ListUsers.
//
// It was extracted when this package still exported a second name for the same
// page query (List, which omitted the total count and had drifted into an
// independently-maintained copy of the SQL). That alias was removed in v0.25.0;
// the helper is kept because ListUsers reads better with the count query and the
// page query separated, and because batch 11's tenancy predicate has one place
// to land instead of two.
func (r *UserRepository) listUsersPage(ctx context.Context, limit, offset int) ([]*models.User, error) {
	query := `
		SELECT id, email, name, oidc_sub, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	users := make([]*models.User, 0)
	for rows.Next() {
		user := &models.User{}
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Name,
			&user.OIDCSub,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, user)
	}

	return users, rows.Err()
}

// ListUsers retrieves a paginated list of users
func (r *UserRepository) ListUsers(ctx context.Context, limit, offset int) ([]*models.User, int, error) {
	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM users`
	err := r.db.QueryRowContext(ctx, countQuery).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	users, err := r.listUsersPage(ctx, limit, offset)
	if err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

// GetOrCreateUserFromOIDC gets or creates a user from OIDC authentication.
//
// emailVerified MUST carry the identity provider's `email_verified` signal for
// the incoming login (see oidc.Provider.ExtractUserInfo). It gates the two paths
// that establish a NEW email-to-identity binding: linking a pre-provisioned
// account and creating a brand-new account. A returning user (matched by
// oidc_sub) is unaffected. Refusing an unverified email closes the pre-
// provisioned-account takeover path where an IdP lets a principal assert an
// unverified email that matches an existing account.
func (r *UserRepository) GetOrCreateUserFromOIDC(ctx context.Context, oidcSub, email, name string, emailVerified bool) (*models.User, error) {
	// Try to find existing user by OIDC sub. A miss is the ordinary first-login
	// path, so ErrNotFound is absorbed here and falls through to the link/create
	// paths below; any OTHER error is a real failure and must not be mistaken for
	// "no such user", which would take a login down the account-creation path on
	// a transient database fault.
	user, err := r.GetUserByOIDCSub(ctx, oidcSub)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	if err == nil {
		// User exists, update email and name if changed
		if user.Email != email || user.Name != name {
			user.Email = email
			user.Name = name
			err = r.UpdateUser(ctx, user)
			if err != nil {
				return nil, err
			}
		}
		return user, nil
	}

	// No user found by OIDC sub — check for an existing user by email.
	// Only a PRE-PROVISIONED account whose oidc_sub is not yet set (setup wizard)
	// may be linked to this OIDC identity. If an account with this email already
	// has a DIFFERENT oidc_sub, refuse rather than silently re-point it: doing so
	// would let anyone able to present a matching email (e.g. an unverified email
	// asserted by another provider) hijack the established account. Re-linking a
	// changed sub is an explicit administrative action, not an implicit login
	// side effect.
	emailUser, err := r.GetUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	if err == nil {
		if emailUser.OIDCSub != nil && *emailUser.OIDCSub != oidcSub {
			return nil, fmt.Errorf("oidc account linking refused: email %q is already linked to a different OIDC subject", email)
		}
		// Linking a pre-provisioned account to this identity establishes a new
		// email->identity binding, so require a verified email.
		if !emailVerified {
			return nil, fmt.Errorf("oidc account linking refused: email %q is not verified by the identity provider", email)
		}
		// Link the OIDC identity to the pre-provisioned account. This is a
		// compare-and-set UPDATE (WHERE ... AND oidc_sub IS NULL), not a plain
		// UpdateUser: two concurrent link attempts for the SAME email but
		// DIFFERENT oidc_sub (e.g. an automated SCIM sync racing this user's
		// first interactive SSO login) must not both "win" last-write-wins, since
		// neither a transaction nor the UNIQUE(oidc_sub) constraint guards this
		// specific path — the constraint only fires across two INSERTed rows, not
		// two UPDATEs of the same row. Mirrors the ON CONFLICT (oidc_sub) DO
		// NOTHING race guard the brand-new-account INSERT path already has below.
		linked, err := r.linkOIDCIdentity(ctx, emailUser.ID, oidcSub, email, name)
		if err != nil {
			return nil, err
		}
		if linked {
			emailUser.OIDCSub = &oidcSub
			emailUser.Email = email
			emailUser.Name = name
			return emailUser, nil
		}

		// Lost the race: some other request linked this row's oidc_sub first.
		// Re-read the row and decide based on what actually won rather than
		// trusting our stale in-memory copy — mirroring the INSERT path's
		// re-read-the-winner fallback.
		winner, werr := r.GetUserByID(ctx, emailUser.ID)
		if errors.Is(werr, ErrNotFound) {
			return nil, fmt.Errorf("oidc account linking: user %s vanished while linking", emailUser.ID)
		}
		if werr != nil {
			return nil, werr
		}
		if winner.OIDCSub != nil && *winner.OIDCSub != oidcSub {
			return nil, fmt.Errorf("oidc account linking refused: email %q is already linked to a different OIDC subject", email)
		}
		return winner, nil
	}

	// Creating a brand-new account keyed on this email also establishes a new
	// email->identity binding; require a verified email to prevent squatting.
	if !emailVerified {
		return nil, fmt.Errorf("oidc account creation refused: email %q is not verified by the identity provider", email)
	}

	// Create the new user. This INSERT (rather than a call to CreateUser) uses
	// ON CONFLICT (oidc_sub) DO NOTHING so that two concurrent first logins for
	// the SAME brand-new identity (double-tab, browser back/forward replay of the
	// callback URL, or a client retry after a timeout — realistic triggers since
	// there is no transaction or SELECT ... FOR UPDATE around the two prior
	// existence checks) don't surface a raw unique-constraint error to the login
	// flow: the losing goroutine falls back to re-reading and returning the
	// winner's row, making GetOrCreateUserFromOIDC idempotent under this race.
	newUser := &models.User{
		ID:        uuid.New().String(),
		Email:     email,
		Name:      name,
		OIDCSub:   &oidcSub,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	insert := `
		INSERT INTO users (id, email, name, oidc_sub, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (oidc_sub) DO NOTHING
	`
	result, err := r.db.ExecContext(ctx, insert,
		newUser.ID, newUser.Email, newUser.Name, newUser.OIDCSub, newUser.CreatedAt, newUser.UpdatedAt,
	)
	if err != nil {
		// The ON CONFLICT arbiter above only covers oidc_sub; if the concurrent
		// winner's row is visible to this constraint check before oidc_sub's (an
		// implementation-defined ordering), the same race can instead surface as a
		// unique-violation on email — since both rows are the SAME login retried,
		// that still means "someone else already created this identity", so fall
		// back the same way rather than treating it as a distinct error.
		if !isUniqueViolation(err) {
			return nil, fmt.Errorf("failed to create user from oidc: %w", err)
		}
	} else {
		// A driver that cannot report RowsAffected here leaves "did my INSERT
		// land?" unanswerable. Reporting that as zero would silently send a
		// successful creation down the lost-the-race re-read path; surface it.
		n, aerr := result.RowsAffected()
		if aerr != nil {
			return nil, fmt.Errorf("failed to read rows affected creating user from oidc: %w", aerr)
		}
		if n > 0 {
			return newUser, nil
		}
	}

	// Either RowsAffected was 0 (ON CONFLICT suppressed our insert) or the insert
	// hit the unique-violation fallback above: a concurrent request already
	// created this identity. Return the winner's row instead of erroring.
	winner, werr := r.GetUserByOIDCSub(ctx, oidcSub)
	if werr == nil {
		return winner, nil
	}
	if !errors.Is(werr, ErrNotFound) {
		return nil, werr
	}
	// Exceptionally unlikely: the conflict was detected but the row is gone by
	// the time we re-read (e.g. deleted between the conflict and this SELECT).
	return nil, fmt.Errorf("oidc user creation: conflicting row for oidc_sub %q not found on re-read", oidcSub)
}

// Count returns the total number of users
func (r *UserRepository) Count(ctx context.Context) (int, error) {
	var total int
	query := `SELECT COUNT(*) FROM users`
	err := r.db.QueryRowContext(ctx, query).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}
	return total, nil
}

// Search searches for users by email or name
func (r *UserRepository) Search(ctx context.Context, query string, limit, offset int) ([]*models.User, error) {
	searchQuery := `
		SELECT id, email, name, oidc_sub, created_at, updated_at
		FROM users
		WHERE email ILIKE $1 OR name ILIKE $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	searchPattern := "%" + escapeLikePattern(query) + "%"
	rows, err := r.db.QueryContext(ctx, searchQuery, searchPattern, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to search users: %w", err)
	}
	defer rows.Close()

	users := make([]*models.User, 0)
	for rows.Next() {
		user := &models.User{}
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Name,
			&user.OIDCSub,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, user)
	}

	return users, rows.Err()
}

// GetUserWithOrgRoles retrieves a user with their per-organization role
// template information.
//
// Returns an error wrapping ErrNotFound when no user has that ID. A user with
// no memberships is NOT a miss — that returns the user with an empty
// Memberships slice.
func (r *UserRepository) GetUserWithOrgRoles(ctx context.Context, userID string) (*models.UserWithOrgRoles, error) {
	// First get the basic user info. ErrNotFound propagates unchanged: the
	// distinction this method needs to preserve is "no such user" (an error)
	// versus "a user with no memberships" (a value with an empty slice).
	user, err := r.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Then get all memberships with role templates (see membership.go for the
	// shared query constant and scan helper).
	rows, err := r.db.QueryContext(ctx, userMembershipByUserQuery, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user memberships: %w", err)
	}
	defer rows.Close()

	memberships := make([]models.UserMembership, 0)
	for rows.Next() {
		m := models.UserMembership{}
		if err := scanUserMembership(rows, &m); err != nil {
			return nil, err
		}
		memberships = append(memberships, m)
	}

	return &models.UserWithOrgRoles{
		User:        *user,
		Memberships: memberships,
	}, rows.Err()
}

// loadMembershipsForUsers bulk-fetches memberships for a slice of users in a single
// database round trip, then attaches them to per-user UserWithOrgRoles structs.
// The returned slice preserves the order of the input users slice.
func (r *UserRepository) loadMembershipsForUsers(ctx context.Context, users []*models.User) ([]*models.UserWithOrgRoles, error) {
	result := make([]*models.UserWithOrgRoles, len(users))
	for i, u := range users {
		result[i] = &models.UserWithOrgRoles{
			User:        *u,
			Memberships: []models.UserMembership{},
		}
	}

	if len(users) == 0 {
		return result, nil
	}

	userIDs := make([]string, len(users))
	for i, u := range users {
		userIDs[i] = u.ID
	}

	// See membership.go for the shared query constant and scan helper.
	rows, err := r.db.QueryContext(ctx, userMembershipByUserIDsQuery, pq.Array(userIDs))
	if err != nil {
		return nil, fmt.Errorf("failed to load memberships for users: %w", err)
	}
	defer rows.Close()

	// Index result by user ID for O(1) lookup when attaching memberships
	resultByUserID := make(map[string]*models.UserWithOrgRoles, len(result))
	for _, uwor := range result {
		resultByUserID[uwor.User.ID] = uwor
	}

	for rows.Next() {
		var userID string
		m := models.UserMembership{}
		// userID is the one extra leading column this bulk query selects.
		if err := scanUserMembership(rows, &m, &userID); err != nil {
			return nil, err
		}
		if uwor, ok := resultByUserID[userID]; ok {
			uwor.Memberships = append(uwor.Memberships, m)
		}
	}

	return result, rows.Err()
}

// ListUsersWithMemberships returns a paginated list of users with their organization
// memberships fetched in a single additional query (2 queries total, not N+1).
func (r *UserRepository) ListUsersWithMemberships(ctx context.Context, limit, offset int) ([]*models.UserWithOrgRoles, int, error) {
	users, total, err := r.ListUsers(ctx, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	result, err := r.loadMembershipsForUsers(ctx, users)
	return result, total, err
}

// SearchWithMemberships searches users and returns results with their organization memberships.
func (r *UserRepository) SearchWithMemberships(ctx context.Context, query string, limit, offset int) ([]*models.UserWithOrgRoles, error) {
	users, err := r.Search(ctx, query, limit, offset)
	if err != nil {
		return nil, err
	}
	return r.loadMembershipsForUsers(ctx, users)
}
