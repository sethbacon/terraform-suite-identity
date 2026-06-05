package models

import "time"

// AuditLog records a mutating action for the audit trail.
type AuditLog struct {
	ID             string                 `db:"id" json:"id"`
	UserID         *string                `db:"user_id" json:"user_id,omitempty"`
	OrganizationID *string                `db:"organization_id" json:"organization_id,omitempty"`
	Action         string                 `db:"action" json:"action"`
	ResourceType   *string                `db:"resource_type" json:"resource_type,omitempty"`
	ResourceID     *string                `db:"resource_id" json:"resource_id,omitempty"`
	IPAddress      *string                `db:"ip_address" json:"ip_address,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt      time.Time              `db:"created_at" json:"created_at"`
}
