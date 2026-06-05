package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// AuditRepository is the data-access layer for audit logs.
type AuditRepository struct {
	db *sql.DB
}

// NewAuditRepository constructs an AuditRepository over the given connection.
func NewAuditRepository(db *sql.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

func (r *AuditRepository) CreateAuditLog(ctx context.Context, log *models.AuditLog) error {
	metadataJSON, err := json.Marshal(log.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO audit_logs (user_id, organization_id, action, resource_type, resource_id, ip_address, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		log.UserID, log.OrganizationID, log.Action, log.ResourceType, log.ResourceID, log.IPAddress, metadataJSON,
	)
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}
	return nil
}

func (r *AuditRepository) ListAuditLogs(ctx context.Context, offset, limit int) ([]*models.AuditLog, int, error) {
	var total int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_logs").Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id, user_id, organization_id, action, resource_type, resource_id, ip_address, metadata, created_at
         FROM audit_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var logs []*models.AuditLog
	for rows.Next() {
		var l models.AuditLog
		var metadataJSON []byte
		if err := rows.Scan(&l.ID, &l.UserID, &l.OrganizationID, &l.Action, &l.ResourceType, &l.ResourceID, &l.IPAddress,
			&metadataJSON, &l.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("failed to scan audit log: %w", err)
		}
		if len(metadataJSON) > 0 {
			_ = json.Unmarshal(metadataJSON, &l.Metadata)
		}
		logs = append(logs, &l)
	}
	return logs, total, nil
}
