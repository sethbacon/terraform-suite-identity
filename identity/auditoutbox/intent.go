// intent.go carries the contract a privileged mutation is held to: the audit
// record is written INSIDE the mutation's own transaction, or the mutation does
// not happen.
package auditoutbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrNoOutbox is returned when a mutation path has nowhere to record its audit
// intent.
//
// A privileged mutation with no outbox must not proceed. This is the
// fail-closed answer at the Go layer; the constraint trigger in ddl.go is the
// one that holds even when this check is bypassed.
var ErrNoOutbox = errors.New("identity/auditoutbox: outbox not configured")

// ErrIntentIncomplete marks an Intent that cannot be audited meaningfully.
// Rejected before the mutation rather than stored and puzzled over later.
var ErrIntentIncomplete = errors.New("identity/auditoutbox: audit intent is incomplete")

// ErrIntentRequired is returned when a privileged mutation is attempted with no
// IntentWriter.
//
// NOT AN OPTIONAL PARAMETER, AND NOT A WARNING. The failure this exists for is
// the one registry hit (terraform-registry-backend #766): the audit entry was
// written after the mutation, on a different connection, and a failure was
// logged while the mutation still reported success — so the highest-privilege
// operation in the product could commit unaudited. Take an IntentWriter as a
// mandatory parameter and "forgot to audit it" becomes a compile-time omission
// that fails closed at runtime; Guard (guard.go) then fails the build when a
// new mutation path is written without one.
var ErrIntentRequired = errors.New("identity/auditoutbox: privileged mutation requires an audit intent writer")

// IntentWriter writes the audit intent describing a mutation into that
// mutation's own transaction.
//
// A function rather than a repository handle, deliberately: a repository that
// takes one does not need to know what an audit record looks like or where it
// eventually lands. It knows only that something has to be written before the
// commit, and that a refusal here has to abort the mutation.
type IntentWriter func(ctx context.Context, tx *sql.Tx) error

// RequireIntentWriter reports ErrIntentRequired when w is nil.
//
// The one line every privileged accessor starts with, so the refusal is one
// sentinel across every repository in every app rather than a per-repository
// error string a caller cannot match on. It runs BEFORE the database is
// touched: an unaudited mutation must not reach a connection at all.
func RequireIntentWriter(w IntentWriter) error {
	if w == nil {
		return ErrIntentRequired
	}
	return nil
}

// Intent is one audit record, captured in the same transaction as the mutation
// it describes and delivered afterwards.
//
// The field set is the destination's own, so delivery is a copy rather than a
// translation. ActorEmail is denormalised for the same reason
// identity.audit_logs.actor_email is: the entry must stay attributable after the
// user row is gone.
type Intent struct {
	// EventID is the stable identity of this event. It becomes the destination
	// row's id, so it is what makes redelivery idempotent. Left empty, Enqueue
	// mints one and writes it back.
	EventID string
	// OccurredAt is when the audited event happened, NOT when it was delivered.
	// Defaulted to now() by Enqueue.
	OccurredAt time.Time
	// Action is the dotted event name ("platform_admin.granted"). Required, and
	// matched verbatim by the constraint trigger.
	Action string
	// ActorUserID is the acting principal, nil for an unattributable event.
	ActorUserID *string
	// ActorEmail is the actor's address as it stood at the time.
	//
	// SET IT. This package does not resolve it from a users table the way
	// identity/store's CreateAuditLog does, because under issue #206 identity
	// may live in another schema or another database entirely — a join across
	// that boundary is exactly what the model forbids. The address is known at
	// intent time, on the request path; nothing downstream can recover it.
	ActorEmail *string
	// OrganizationID is the owning organization, nil for platform-wide events.
	OrganizationID *string
	// ResourceType and ResourceID name the thing acted upon. Both are matched
	// by the constraint trigger, so they are what binds this record to the row
	// that was mutated.
	ResourceType *string
	ResourceID   *string
	// IPAddress is the client address the request arrived from.
	IPAddress *string
	// Metadata is the free-form detail, stored as JSONB.
	Metadata map[string]interface{}
}

// pendingIntent is an outbox row the relay has claimed for delivery.
type pendingIntent struct {
	Intent
	Attempts int
}

// Entry is a delivered intent as an external shipper sees it. It is a value
// type with no database in it, so a Shipper implementation cannot become a
// second writer of the audit trail.
type Entry struct {
	Timestamp      time.Time              `json:"timestamp"`
	EventID        string                 `json:"event_id"`
	Action         string                 `json:"action"`
	UserID         string                 `json:"user_id,omitempty"`
	ActorEmail     string                 `json:"actor_email,omitempty"`
	OrganizationID string                 `json:"organization_id,omitempty"`
	ResourceType   string                 `json:"resource_type,omitempty"`
	ResourceID     string                 `json:"resource_id,omitempty"`
	IPAddress      string                 `json:"ip_address,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// Shipper forwards delivered entries to an external destination (a SIEM, a log
// aggregator). Shipping is best-effort and never the audit trail — see relay.go
// for why a shipping failure does not retain the intent.
type Shipper interface {
	Ship(ctx context.Context, entry *Entry) error
}

// marshalMetadata renders Metadata for a JSONB column. A nil map is sent as SQL
// NULL (a nil interface{}, the same convention identity/store uses) rather than
// the string "null".
func marshalMetadata(m map[string]interface{}) (interface{}, error) {
	if m == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("%w: metadata is not JSON-encodable: %w", ErrIntentIncomplete, err)
	}
	return encoded, nil
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
