// Package auditoutbox is the transactional audit outbox: the mechanism that
// makes "no privileged mutation commits without its audit record" a property
// the database enforces rather than one the code intends.
//
// # Why an outbox and not a second write
//
// Under the identity model (issue #206) identity is shared and authorization is
// per-app: `identity.users` may live in another schema, or another database,
// from the `audit_logs` an app records its own actions in. A mutation and its
// audit entry therefore cannot always share a transaction with the identity
// store, and the pattern that results — mutate, then write the audit entry,
// then log an error when the second write fails and report success anyway — is
// how the highest privilege in a product changes hands with no record of it.
// That is terraform-registry-backend #766, verbatim.
//
// The outbox removes the divergence by removing the second write from the
// request path. The audit INTENT is inserted into the app's own outbox table,
// on the same connection and in the same transaction as the mutation, so the
// two commit together or not at all. A Relay delivers intents to the
// destination table and to any configured Shipper afterwards, at least once.
//
// # The three layers
//
//  1. A DEFERRABLE INITIALLY DEFERRED constraint trigger on the mutated table
//     re-checks AT COMMIT that this transaction wrote a matching intent
//     (ddl.go). It matches on pg_current_xact_id() rather than a foreign key
//     because "same transaction" is the property — a foreign key would be
//     satisfied by an intent written days earlier.
//  2. Repositories take a mandatory IntentWriter; nil is ErrIntentRequired
//     before the database is touched (intent.go).
//  3. Guard is a source scan that fails the build when a function writes the
//     protected table without taking one (guard.go).
//
// # What the app owns
//
// Everything physical. This package ships no migration and creates no table:
// the outbox and the destination are the app's, in the app's schema, created by
// the app's own migration set from the DDL this package renders (OutboxDDL,
// TriggerSpec.DDL). Every statement here addresses a name the app supplied.
package auditoutbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Outbox is the audit outbox table on the app's own connection.
type Outbox struct {
	db    *sql.DB
	table table

	// Statements are built once at construction: the table name is
	// interpolated, so building them per call would be the same interpolation
	// repeated on every privileged mutation.
	insertSQL  string
	claimSQL   string
	markSQL    string
	failSQL    string
	backlogSQL string
	pruneSQL   string
}

// outboxColumns is the projection the claim scan reads, in one place so the
// query and the scan cannot drift.
const outboxColumns = `event_id, occurred_at, action, actor_user_id, actor_email,
	organization_id, resource_type, resource_id, ip_address, metadata, attempts`

// New constructs an Outbox over the app's DOMAIN connection — the SAME
// connection the privileged mutations run on.
//
// Handing it the identity connection instead would reintroduce exactly the
// cross-connection split this exists to remove, so the caller must pass the
// connection its mutations use. DB() exists so that can be asserted at wiring
// time rather than discovered when the trigger refuses a commit.
//
// outboxTable is the app's own table, optionally schema-qualified
// ("registry.audit_outbox"). Unqualified, it is resolved by the connection's
// search_path exactly as every other unqualified name in this module is; Verify
// reports which schema that turned out to be.
func New(db *sql.DB, outboxTable string) (*Outbox, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: no database handle supplied", ErrNoOutbox)
	}
	t, err := parseTable("outbox table", outboxTable)
	if err != nil {
		return nil, err
	}

	name := t.sql()
	return &Outbox{
		db:    db,
		table: t,
		insertSQL: `INSERT INTO ` + name + ` (
			event_id, occurred_at, action, actor_user_id, actor_email,
			organization_id, resource_type, resource_id, ip_address, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		claimSQL: `SELECT ` + outboxColumns + `
			  FROM ` + name + `
			 WHERE delivered_at IS NULL
			 ORDER BY occurred_at ASC, event_id ASC
			 LIMIT $1
			   FOR UPDATE SKIP LOCKED`,
		markSQL: `UPDATE ` + name + `
			    SET delivered_at = now(), attempts = attempts + 1, last_error = NULL
			  WHERE event_id = $1`,
		failSQL: `UPDATE ` + name + `
			    SET attempts = attempts + 1, last_error = $2
			  WHERE event_id = $1`,
		backlogSQL: `SELECT count(*),
			       count(*) FILTER (WHERE attempts > 0),
			       min(occurred_at)
			  FROM ` + name + `
			 WHERE delivered_at IS NULL`,
		pruneSQL: `DELETE FROM ` + name + `
			 WHERE event_id IN (
			       SELECT event_id FROM ` + name + `
			        WHERE delivered_at IS NOT NULL AND delivered_at < $1
			        ORDER BY delivered_at ASC
			        LIMIT $2)`,
	}, nil
}

// Table returns the outbox table name as it was supplied.
func (o *Outbox) Table() string {
	if o == nil {
		return ""
	}
	return o.table.String()
}

// DB exposes the connection the outbox lives on, so a caller can assert it is
// the same one its mutations use.
func (o *Outbox) DB() *sql.DB {
	if o == nil {
		return nil
	}
	return o.db
}

// Enqueue writes intent into the outbox INSIDE tx — the caller's transaction,
// the one carrying the mutation being audited. It does not commit; that is the
// caller's, so the record and the mutation land together or neither does.
//
// A nil Outbox or a nil tx is an error rather than a no-op. Both mean the
// intent would be lost, and a lost audit intent must fail the mutation, not
// accompany it silently.
//
// EventID is filled in when empty, and written back into intent so the caller
// can log or return it.
func (o *Outbox) Enqueue(ctx context.Context, tx *sql.Tx, intent *Intent) error {
	if o == nil || o.db == nil {
		return ErrNoOutbox
	}
	if tx == nil {
		return fmt.Errorf("%w: no transaction to enlist in; the intent must be written in the "+
			"mutation's own transaction or it is not an outbox", ErrNoOutbox)
	}
	if intent == nil {
		return fmt.Errorf("%w: nil intent", ErrIntentIncomplete)
	}
	if intent.Action == "" {
		return fmt.Errorf("%w: action is empty; the constraint trigger matches on it verbatim", ErrIntentIncomplete)
	}
	if intent.EventID == "" {
		intent.EventID = uuid.New().String()
	}
	if intent.OccurredAt.IsZero() {
		intent.OccurredAt = time.Now().UTC()
	}

	metadataArg, err := marshalMetadata(intent.Metadata)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, o.insertSQL,
		intent.EventID,
		intent.OccurredAt,
		intent.Action,
		intent.ActorUserID,
		intent.ActorEmail,
		intent.OrganizationID,
		intent.ResourceType,
		intent.ResourceID,
		intent.IPAddress,
		metadataArg,
	); err != nil {
		return fmt.Errorf("failed to enqueue audit intent into %s: %w", o.table, err)
	}
	return nil
}

// Writer binds intent to this outbox and returns the IntentWriter a privileged
// repository takes as a mandatory parameter.
//
// It NEVER returns nil, including on a nil Outbox. A nil writer is the one
// thing RequireIntentWriter refuses, so returning one from a misconfigured
// outbox would turn "audit is not wired up" into "this call site forgot to
// audit" — the same failure with the wrong diagnosis. A writer from a nil
// Outbox reports ErrNoOutbox when the mutation tries to use it.
func (o *Outbox) Writer(intent *Intent) IntentWriter {
	return func(ctx context.Context, tx *sql.Tx) error {
		return o.Enqueue(ctx, tx, intent)
	}
}

// claim locks up to limit undelivered intents inside tx.
//
// FOR UPDATE SKIP LOCKED, not a plain FOR UPDATE: several replicas run the
// relay, and a replica that blocks behind another's batch delivers nothing while
// it waits. SKIP LOCKED lets each take a disjoint set, and the rows one replica
// skips are picked up on the next cycle.
//
// Oldest first, so a backlog drains in the order events happened.
func (o *Outbox) claim(ctx context.Context, tx *sql.Tx, limit int) ([]pendingIntent, error) {
	rows, err := tx.QueryContext(ctx, o.claimSQL, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to claim audit intents from %s: %w", o.table, err)
	}
	defer func() { _ = rows.Close() }()

	var claimed []pendingIntent
	for rows.Next() {
		var p pendingIntent
		var metadata []byte
		if err := rows.Scan(&p.EventID, &p.OccurredAt, &p.Action, &p.ActorUserID, &p.ActorEmail,
			&p.OrganizationID, &p.ResourceType, &p.ResourceID, &p.IPAddress, &metadata, &p.Attempts); err != nil {
			return nil, fmt.Errorf("failed to scan audit intent: %w", err)
		}
		if len(metadata) > 0 {
			if err := json.Unmarshal(metadata, &p.Metadata); err != nil {
				// The record still delivers; only the detail is unreadable.
				// Dropping the whole entry over a bad metadata blob would lose
				// the who/what/when, which is the part that matters.
				p.Metadata = map[string]interface{}{"metadata_unreadable": err.Error()}
			}
		}
		claimed = append(claimed, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read claimed audit intents: %w", err)
	}
	return claimed, nil
}

// markDelivered records a successful delivery inside tx.
func (o *Outbox) markDelivered(ctx context.Context, tx *sql.Tx, eventID string) error {
	if _, err := tx.ExecContext(ctx, o.markSQL, eventID); err != nil {
		return fmt.Errorf("failed to mark audit intent %s delivered: %w", eventID, err)
	}
	return nil
}

// recordFailure counts an attempt and keeps the reason, leaving delivered_at
// NULL so the intent is retried. The row stays in the backlog on purpose: an
// audit intent is never dropped for failing to deliver.
func (o *Outbox) recordFailure(ctx context.Context, tx *sql.Tx, eventID string, cause error) error {
	if _, err := tx.ExecContext(ctx, o.failSQL, eventID, cause.Error()); err != nil {
		return fmt.Errorf("failed to record audit intent %s failure: %w", eventID, err)
	}
	return nil
}

// Backlog is what an operator needs to see: how many audit records exist but
// have not reached the destination, how long the oldest has been waiting, and
// how many have already failed at least once.
type Backlog struct {
	// Pending is the number of undelivered intents.
	Pending int64
	// Failed is the subset of Pending that has failed at least one attempt.
	// Pending alone cannot distinguish "written a moment ago" from "stuck".
	Failed int64
	// OldestPending is when the oldest undelivered event occurred. Zero when
	// Pending is 0.
	OldestPending time.Time
}

// Backlog reads the current undelivered depth.
func (o *Outbox) Backlog(ctx context.Context) (Backlog, error) {
	if o == nil || o.db == nil {
		return Backlog{}, ErrNoOutbox
	}
	var b Backlog
	var oldest sql.NullTime
	if err := o.db.QueryRowContext(ctx, o.backlogSQL).Scan(&b.Pending, &b.Failed, &oldest); err != nil {
		return Backlog{}, fmt.Errorf("failed to read the audit outbox backlog from %s: %w", o.table, err)
	}
	if oldest.Valid {
		b.OldestPending = oldest.Time
	}
	return b, nil
}

// PruneDelivered removes delivered intents older than before, in batches of at
// most limit, and returns how many rows went.
//
// ONLY DELIVERED ROWS. The undelivered backlog is never pruned — deleting an
// intent that never reached the destination would destroy the record this whole
// design exists to keep. That is why the backlog is reported and alarmed on
// instead: it can only be drained by delivering it.
func (o *Outbox) PruneDelivered(ctx context.Context, before time.Time, limit int) (int64, error) {
	if o == nil || o.db == nil {
		return 0, ErrNoOutbox
	}
	if limit <= 0 {
		limit = defaultPruneLimit
	}
	res, err := o.db.ExecContext(ctx, o.pruneSQL, before, limit)
	if err != nil {
		return 0, fmt.Errorf("failed to prune delivered audit intents from %s: %w", o.table, err)
	}
	pruned, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to count pruned audit intents: %w", err)
	}
	return pruned, nil
}

// defaultPruneLimit bounds one prune when the caller names no limit.
const defaultPruneLimit = 1000

// outboxRequiredColumns is every column this package's statements name, so
// Verify fails at startup on a table that would fail at the first privileged
// mutation.
var outboxRequiredColumns = []string{
	"event_id", "txid", "occurred_at", "action", "actor_user_id", "actor_email",
	"organization_id", "resource_type", "resource_id", "ip_address", "metadata",
	"delivered_at", "attempts", "last_error",
}

// Verify asserts that the outbox table exists on this connection and carries
// every column this package's statements name, and returns the
// schema-qualified name it resolved to.
//
// Call it once at startup and log the name. The name is the point: the table is
// app-owned, this package does not know which schema it should be in, and an
// unqualified name is placed by the connection's search_path. A deployment that
// changes that path, or acquires a second outbox table in another schema, sees
// it in that line instead of discovering it as an audit trail that stopped
// draining.
func (o *Outbox) Verify(ctx context.Context) (string, error) {
	if o == nil || o.db == nil {
		return "", ErrNoOutbox
	}
	shape, err := describeTable(ctx, o.db, o.table)
	if err != nil {
		return "", err
	}
	if !shape.exists() {
		return "", fmt.Errorf("%w: %s resolves to nothing on this connection (search_path %q). "+
			"This package creates no table — the app owns it. Apply auditoutbox.OutboxDDL(%q) from "+
			"the app's own migration set", ErrOutboxShape, o.table, shape.searchPath, o.table.String())
	}
	var missing []string
	for _, column := range outboxRequiredColumns {
		if !shape.has(column) {
			missing = append(missing, column)
		}
	}
	if len(missing) > 0 {
		return shape.qualified, fmt.Errorf("%w: %s is missing %v, which this package's statements name. "+
			"auditoutbox.OutboxDDL is the canonical definition; reconcile the app's migration set against it",
			ErrOutboxShape, shape.qualified, missing)
	}
	return shape.qualified, nil
}
