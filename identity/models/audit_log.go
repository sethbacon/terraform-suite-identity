package models

import "time"

// AuditLog represents an audit log entry for tracking user actions.
//
// UserID and OrganizationID are a HISTORICAL record of who acted and for which
// organization at the time of the event, not live references: since v0.25.0
// audit_logs carries no foreign key to users or organizations, so deleting
// either leaves these values in place rather than blanking them (issue #142). A
// NULL therefore has exactly one meaning on each column — the writer asserted no
// actor, or no owning organization — and cannot be manufactured by a delete.
type AuditLog struct {
	ID             string
	UserID         *string // Nullable for system actions
	OrganizationID *string
	Action         string                 // "module.upload", "provider.delete", "user.create"
	ResourceType   *string                // "module", "provider", "user", "api_key"
	ResourceID     *string                // UUID of affected resource
	Metadata       map[string]interface{} // JSONB: additional context
	IPAddress      *string                // Client IP
	CreatedAt      time.Time

	// ActorEmail is the acting user's address AS IT STOOD when the entry was
	// written, denormalised into the row and never updated afterwards. It is
	// STORED (unlike UserEmail/UserName below) precisely so attribution does not
	// depend on the users row still existing: once a user is deleted, UserID is
	// a uuid nothing can resolve, and an unresolvable actor is not a trail.
	//
	// CreateAuditLog fills it from the users table when the caller leaves it nil
	// and UserID is set, so callers need do nothing; set it explicitly to record
	// an actor this database does not hold a users row for.
	ActorEmail *string `json:"actor_email,omitempty"`

	// Transient fields populated via LEFT JOIN with users table (never stored in audit_logs).
	// They report the actor's CURRENT identity and are nil once the user is
	// deleted — deliberately not back-filled from ActorEmail, so a reader can
	// tell a live actor from a retained one.
	UserEmail *string `json:"user_email,omitempty"`
	UserName  *string `json:"user_name,omitempty"`
}
