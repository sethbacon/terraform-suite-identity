// audit_repository.go implements AuditRepository, providing database queries for writing
// and retrieving audit log entries with support for filtered queries across users and resources.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// AuditRepository handles audit log database operations
type AuditRepository struct {
	db *sql.DB
}

// NewAuditRepository creates a new AuditRepository
func NewAuditRepository(db *sql.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

// AuditFilters contains filters for querying audit logs
type AuditFilters struct {
	UserID         *string
	UserEmail      *string // Partial match (ILIKE) — filters by the associated user's email
	OrganizationID *string
	Action         *string
	ResourceType   *string
	StartDate      *time.Time
	EndDate        *time.Time
}

// CreateAuditLog creates a new audit log entry.
//
// It stamps log.ID and log.CreatedAt, and — when the caller left ActorEmail nil
// and UserID set — resolves the actor's address from the users table IN THE SAME
// STATEMENT and writes it back into log. That denormalised copy is what keeps
// the entry attributable after the user is deleted: audit_logs has carried no
// foreign key to users since v0.25.0, so UserID survives the delete, but a uuid
// whose users row is gone resolves to nobody (issue #142).
//
// Resolution is a scalar sub-select on the users primary key rather than a
// second round trip, so a caller that does nothing still gets an attributed row
// at the cost of one index lookup. A caller that DOES set ActorEmail wins: that
// is the path for recording an actor this database holds no users row for (a
// federated entry from a sibling application, for instance).
func (r *AuditRepository) CreateAuditLog(ctx context.Context, log *models.AuditLog) error {
	log.ID = uuid.New().String()
	log.CreatedAt = time.Now()

	// Marshal metadata to JSONB; use nil interface so lib/pq sends SQL NULL when absent.
	var metadataArg interface{}
	if log.Metadata != nil {
		metadataJSON, err := json.Marshal(log.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal audit log metadata: %w", err)
		}
		metadataArg = metadataJSON
	}

	query := `
		INSERT INTO audit_logs (id, user_id, organization_id, action, resource_type, resource_id, metadata, ip_address, created_at, actor_email)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, COALESCE($10, (SELECT email FROM users WHERE id = $2)))
		RETURNING actor_email
	`

	err := r.db.QueryRowContext(ctx, query,
		log.ID,
		log.UserID,
		log.OrganizationID,
		log.Action,
		log.ResourceType,
		log.ResourceID,
		metadataArg,
		log.IPAddress,
		log.CreatedAt,
		log.ActorEmail,
	).Scan(&log.ActorEmail)
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	return nil
}

// ListAuditLogs retrieves audit logs with optional filters and pagination.
// Results are enriched with user email and name via a LEFT JOIN on the users table.
//
// scope is the MANDATORY tenant constraint (see org_scope.go). It is a
// separate parameter from filters, not another optional filter field, because
// audit_logs is organization-owned and an omitted filter must not mean "every
// organization". Pass OrgScopeAllOrganizations() to read platform-wide.
func (r *AuditRepository) ListAuditLogs(ctx context.Context, filters AuditFilters, scope OrgScope, limit, offset int) ([]*models.AuditLog, int, error) {
	if scope.MatchesNothing() {
		// Fail closed without a round trip. A principal with no memberships has
		// an empty audit trail, not the whole estate's.
		return []*models.AuditLog{}, 0, nil
	}

	countQuery, countArgs, query, args := buildListAuditLogsQueries(filters, scope, limit, offset)

	// Get total count
	var total int
	err := r.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	// Execute query
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer rows.Close()

	logs := make([]*models.AuditLog, 0)
	for rows.Next() {
		log := &models.AuditLog{}
		var metadataJSON []byte

		err := rows.Scan(
			&log.ID,
			&log.UserID,
			&log.OrganizationID,
			&log.Action,
			&log.ResourceType,
			&log.ResourceID,
			&metadataJSON,
			&log.IPAddress,
			&log.CreatedAt,
			&log.ActorEmail,
			&log.UserEmail,
			&log.UserName,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan audit log: %w", err)
		}

		// Unmarshal metadata from JSONB
		if metadataJSON != nil {
			err = json.Unmarshal(metadataJSON, &log.Metadata)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to unmarshal audit log metadata: %w", err)
			}
		}

		logs = append(logs, log)
	}

	return logs, total, rows.Err()
}

// buildListAuditLogsQueries assembles the two statements ListAuditLogs emits —
// the COUNT and the ordered, paginated page query — together with their
// arguments.
//
// It is a separate function so that the SQL a test reasons about is the SQL
// that actually reaches PostgreSQL, byte for byte. The index this query depends
// on (idx_identity_audit_logs_org_created_at, migration 000006) is only useful
// if it matches the predicate AND the ORDER BY that are really produced here, so
// the integration test that EXPLAINs the plan calls this builder rather than
// restating the query — a hand-copied query in a test can drift from the
// emitted one and would then be proving the wrong plan.
//
// The caller is responsible for the MatchesNothing() short-circuit; a
// fail-closed scope reaching here still yields an " AND FALSE" predicate rather
// than an unfiltered query.
func buildListAuditLogsQueries(filters AuditFilters, scope OrgScope, limit, offset int) (countQuery string, countArgs []interface{}, listQuery string, listArgs []interface{}) {
	// Build query with filters
	countQuery = `SELECT COUNT(*) FROM audit_logs al LEFT JOIN users u ON al.user_id = u.id WHERE 1=1`
	// al.actor_email is the RETAINED actor (stored on the row); u.email is the
	// CURRENT one (joined). Both are projected, and neither COALESCEs into the
	// other: a reader must be able to tell "this user still exists" from "this
	// is who acted, and they are gone".
	query := `
		SELECT al.id, al.user_id, al.organization_id, al.action, al.resource_type, al.resource_id,
		       al.metadata, al.ip_address, al.created_at, al.actor_email,
		       u.email AS user_email, u.name AS user_name
		FROM audit_logs al
		LEFT JOIN users u ON al.user_id = u.id
		WHERE 1=1
	`

	args := make([]interface{}, 0)
	paramIndex := 1

	// GUARD audit-scope-list (issue terraform-registry#719): the tenant
	// predicate is applied FIRST and unconditionally, before any caller-supplied
	// filter, so no filter combination can produce an unscoped query.
	countQuery, _ = andScope(countQuery, scope, "al.organization_id", args)
	query, args = andScope(query, scope, "al.organization_id", args)
	paramIndex = len(args) + 1

	// Apply filters
	if filters.UserID != nil {
		countQuery += fmt.Sprintf(` AND al.user_id = $%d`, paramIndex)
		query += fmt.Sprintf(` AND al.user_id = $%d`, paramIndex)
		args = append(args, *filters.UserID)
		paramIndex++
	}

	if filters.UserEmail != nil {
		countQuery += fmt.Sprintf(` AND u.email ILIKE $%d`, paramIndex)
		query += fmt.Sprintf(` AND u.email ILIKE $%d`, paramIndex)
		args = append(args, "%"+escapeLikePattern(*filters.UserEmail)+"%")
		paramIndex++
	}

	if filters.OrganizationID != nil {
		countQuery += fmt.Sprintf(` AND al.organization_id = $%d`, paramIndex)
		query += fmt.Sprintf(` AND al.organization_id = $%d`, paramIndex)
		args = append(args, *filters.OrganizationID)
		paramIndex++
	}

	if filters.Action != nil {
		countQuery += fmt.Sprintf(` AND al.action = $%d`, paramIndex)
		query += fmt.Sprintf(` AND al.action = $%d`, paramIndex)
		args = append(args, *filters.Action)
		paramIndex++
	}

	if filters.ResourceType != nil {
		countQuery += fmt.Sprintf(` AND al.resource_type = $%d`, paramIndex)
		query += fmt.Sprintf(` AND al.resource_type = $%d`, paramIndex)
		args = append(args, *filters.ResourceType)
		paramIndex++
	}

	if filters.StartDate != nil {
		countQuery += fmt.Sprintf(` AND al.created_at >= $%d`, paramIndex)
		query += fmt.Sprintf(` AND al.created_at >= $%d`, paramIndex)
		args = append(args, *filters.StartDate)
		paramIndex++
	}

	if filters.EndDate != nil {
		countQuery += fmt.Sprintf(` AND al.created_at <= $%d`, paramIndex)
		query += fmt.Sprintf(` AND al.created_at <= $%d`, paramIndex)
		args = append(args, *filters.EndDate)
		paramIndex++
	}

	// The COUNT runs with exactly the predicate built so far and none of the
	// pagination arguments, so it is snapshotted before ORDER BY/LIMIT/OFFSET
	// are appended. Copying keeps the two argument lists independent — appending
	// to `args` below must not be able to reach the count's backing array.
	countArgs = make([]interface{}, len(args))
	copy(countArgs, args)

	// Add ordering and pagination. The ORDER BY is part of the hot path, not
	// decoration: idx_identity_audit_logs_org_created_at is
	// (organization_id, created_at DESC) precisely so the tenant predicate and
	// this sort are served by one index rather than an index scan followed by a
	// sort of every row the tenant owns.
	query += fmt.Sprintf(` ORDER BY al.created_at DESC LIMIT $%d OFFSET $%d`, paramIndex, paramIndex+1) // #nosec G202 -- paramIndex is an internal counter for $N placeholder numbering; no user input is interpolated into the query string
	args = append(args, limit, offset)

	return countQuery, countArgs, query, args
}

// GetAuditLog retrieves a single audit log entry by ID within scope.
//
// An entry outside the scope is reported as not found (an error wrapping
// ErrNotFound) rather than forbidden, and by the SAME error a genuinely absent
// entry produces, so the by-id read cannot be used to probe for the existence of
// another organization's audit entries. A scope that matches nothing at all
// short-circuits to that same result without a round trip.
//
// scope is mandatory for the same reason it is mandatory on ListAuditLogs: the
// by-id axis previously carried no tenant predicate at all while the list axis
// had one, which is precisely how terraform-registry#719 stayed open after
// being closed.
func (r *AuditRepository) GetAuditLog(ctx context.Context, logID string, scope OrgScope) (*models.AuditLog, error) {
	if scope.MatchesNothing() {
		return nil, notFound("audit log by id")
	}

	// GUARD audit-scope-byid (issue terraform-registry#719).
	query := `
		SELECT id, user_id, organization_id, action, resource_type, resource_id, metadata, ip_address, created_at, actor_email
		FROM audit_logs
		WHERE id = $1
	`
	args := []interface{}{logID}
	query, args = andScope(query, scope, "organization_id", args)

	log := &models.AuditLog{}
	var metadataJSON []byte

	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&log.ID,
		&log.UserID,
		&log.OrganizationID,
		&log.Action,
		&log.ResourceType,
		&log.ResourceID,
		&metadataJSON,
		&log.IPAddress,
		&log.CreatedAt,
		&log.ActorEmail,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound("audit log by id")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get audit log: %w", err)
	}

	// Unmarshal metadata from JSONB
	if metadataJSON != nil {
		err = json.Unmarshal(metadataJSON, &log.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal audit log metadata: %w", err)
		}
	}

	return log, nil
}

// DeleteAuditLogsBefore deletes audit logs older than cutoff in one batch.
// Returns the number of rows deleted.
//
// With store.WithLegalHolds(table) the batch excludes any row covered by an
// active hold in that table, so an investigation's evidence survives retention.
// Without it the statement is byte-identical to the one this method has always
// emitted — see audit_sweep.go for why the exemption is an option rather than
// part of the statement, and why a consumer without the table must not be
// handed a predicate that references it.
func (r *AuditRepository) DeleteAuditLogsBefore(ctx context.Context, cutoff time.Time, batchSize int, opts ...AuditSweepOption) (int64, error) {
	exemption, err := newAuditSweepFilter(opts).exemption()
	if err != nil {
		return 0, err
	}
	// #nosec G202 -- exemption is not caller data. It is rendered by
	// auditSweepFilter.exemption from a table name validated against
	// identifierPattern and escaped by pgquote.Identifier, plus three
	// compile-time column constants; an unquotable name is returned as the
	// error above rather than pasted in. cutoff and batchSize stay bound.
	query := `
		DELETE FROM audit_logs
		WHERE id IN (
			SELECT id FROM audit_logs WHERE created_at < $1` + exemption + `
			ORDER BY created_at ASC LIMIT $2
		)
	`
	result, err := r.db.ExecContext(ctx, query, cutoff, batchSize)
	if err != nil {
		return 0, fmt.Errorf("failed to delete audit logs before cutoff: %w", err)
	}
	return affectedRows(result, "audit logs before cutoff")
}

// StreamAuditLogs returns rows for the given date range, constrained to scope,
// for efficient streaming. The caller is responsible for closing the returned
// *sql.Rows.
//
// This is the export axis. It is the axis that kept leaking after
// terraform-registry#719 was closed: the fix landed on the list handler, and no
// search rooted at ListAuditLogs reaches a different method in a different file
// serving GET /admin/audit-logs/export. Making scope a required parameter here
// is what stops the next access axis from repeating it.
//
// The projection is part of this method's contract because the caller scans the
// rows itself. It gained al.actor_email in v0.25.0, in COLUMN 10, between
// created_at and the joined user_email/user_name — a caller's Scan must add the
// destination there. The export is the compliance artefact, so it is the last
// place that should omit the attribution that survives a user deletion.
func (r *AuditRepository) StreamAuditLogs(ctx context.Context, startDate, endDate time.Time, scope OrgScope) (*sql.Rows, error) {
	// GUARD audit-scope-export (issue terraform-registry#719).
	query := `
		SELECT al.id, al.user_id, al.organization_id, al.action, al.resource_type, al.resource_id,
		       al.metadata, al.ip_address, al.created_at, al.actor_email,
		       u.email AS user_email, u.name AS user_name
		FROM audit_logs al
		LEFT JOIN users u ON al.user_id = u.id
		WHERE al.created_at >= $1 AND al.created_at <= $2
	`
	args := []interface{}{startDate, endDate}
	query, args = andScope(query, scope, "al.organization_id", args)
	query += ` ORDER BY al.created_at ASC`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to stream audit logs: %w", err)
	}
	return rows, nil
}
