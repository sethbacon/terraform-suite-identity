// audit_repository.go implements AuditRepository, providing database queries for writing
// and retrieving audit log entries with support for filtered queries across users and resources.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
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

// CreateAuditLog creates a new audit log entry
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
		INSERT INTO audit_logs (id, user_id, organization_id, action, resource_type, resource_id, metadata, ip_address, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := r.db.ExecContext(ctx, query,
		log.ID,
		log.UserID,
		log.OrganizationID,
		log.Action,
		log.ResourceType,
		log.ResourceID,
		metadataArg,
		log.IPAddress,
		log.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	return nil
}

// ListAuditLogs retrieves audit logs with optional filters and pagination.
// Results are enriched with user email and name via a LEFT JOIN on the users table.
//
// scope is the MANDATORY tenant constraint (see audit_scope.go). It is a
// separate parameter from filters, not another optional filter field, because
// audit_logs is organization-owned and an omitted filter must not mean "every
// organization". Pass AuditScopeAllOrganizations() to read platform-wide.
func (r *AuditRepository) ListAuditLogs(ctx context.Context, filters AuditFilters, scope AuditScope, limit, offset int) ([]*models.AuditLog, int, error) {
	if scope.MatchesNothing() {
		// Fail closed without a round trip. A principal with no memberships has
		// an empty audit trail, not the whole estate's.
		return []*models.AuditLog{}, 0, nil
	}

	// Build query with filters
	countQuery := `SELECT COUNT(*) FROM audit_logs al LEFT JOIN users u ON al.user_id = u.id WHERE 1=1`
	query := `
		SELECT al.id, al.user_id, al.organization_id, al.action, al.resource_type, al.resource_id,
		       al.metadata, al.ip_address, al.created_at,
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
	if pred, arg := scope.sqlPredicate("al.organization_id", paramIndex); pred != "" {
		countQuery += pred
		query += pred
		if arg != nil {
			args = append(args, arg)
			paramIndex++
		}
	}

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

	// Get total count
	var total int
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	// Add ordering and pagination
	query += fmt.Sprintf(` ORDER BY al.created_at DESC LIMIT $%d OFFSET $%d`, paramIndex, paramIndex+1) // #nosec G202 -- paramIndex is an internal counter for $N placeholder numbering; no user input is interpolated into the query string
	args = append(args, limit, offset)

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

// GetAuditLog retrieves a single audit log entry by ID within scope.
//
// An entry outside the scope is reported as not found (nil, nil) rather than
// forbidden, so the by-id read cannot be used to probe for the existence of
// another organization's audit entries.
//
// scope is mandatory for the same reason it is mandatory on ListAuditLogs: the
// by-id axis previously carried no tenant predicate at all while the list axis
// had one, which is precisely how terraform-registry#719 stayed open after
// being closed.
func (r *AuditRepository) GetAuditLog(ctx context.Context, logID string, scope AuditScope) (*models.AuditLog, error) {
	if scope.MatchesNothing() {
		return nil, nil
	}

	// GUARD audit-scope-byid (issue terraform-registry#719).
	query := `
		SELECT id, user_id, organization_id, action, resource_type, resource_id, metadata, ip_address, created_at
		FROM audit_logs
		WHERE id = $1
	`
	args := []interface{}{logID}
	if pred, arg := scope.sqlPredicate("organization_id", 2); pred != "" {
		query += pred
		if arg != nil {
			args = append(args, arg)
		}
	}

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
	)

	if err == sql.ErrNoRows {
		return nil, nil
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
func (r *AuditRepository) DeleteAuditLogsBefore(ctx context.Context, cutoff time.Time, batchSize int) (int64, error) {
	query := `
		DELETE FROM audit_logs
		WHERE id IN (
			SELECT id FROM audit_logs WHERE created_at < $1 ORDER BY created_at ASC LIMIT $2
		)
	`
	result, err := r.db.ExecContext(ctx, query, cutoff, batchSize)
	if err != nil {
		return 0, fmt.Errorf("failed to delete audit logs before cutoff: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected deleting audit logs: %w", err)
	}
	return n, nil
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
func (r *AuditRepository) StreamAuditLogs(ctx context.Context, startDate, endDate time.Time, scope AuditScope) (*sql.Rows, error) {
	// GUARD audit-scope-export (issue terraform-registry#719).
	query := `
		SELECT al.id, al.user_id, al.organization_id, al.action, al.resource_type, al.resource_id,
		       al.metadata, al.ip_address, al.created_at,
		       u.email AS user_email, u.name AS user_name
		FROM audit_logs al
		LEFT JOIN users u ON al.user_id = u.id
		WHERE al.created_at >= $1 AND al.created_at <= $2
	`
	args := []interface{}{startDate, endDate}
	if pred, arg := scope.sqlPredicate("al.organization_id", 3); pred != "" {
		query += pred
		if arg != nil {
			args = append(args, arg)
		}
	}
	query += ` ORDER BY al.created_at ASC`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to stream audit logs: %w", err)
	}
	return rows, nil
}
