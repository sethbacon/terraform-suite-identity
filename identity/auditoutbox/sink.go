// sink.go is the delivery end of the outbox: it writes a claimed Intent into
// the app's audit table, idempotently.
//
// # Why the sink writes the destination directly
//
// Delivery is at-least-once — that is what makes it survive a crash — so the
// destination has to be able to recognise a record it already holds. The only
// thing that can enforce that is the destination's own primary key, which means
// the id must come from the intent. identity/store's CreateAuditLog mints a
// fresh uuid.New() on every call and overwrites whatever the caller set, so
// redelivering through it would append a second copy of the same event rather
// than collide with the first. The sink therefore owns one INSERT, keyed on the
// intent's EventID, with ON CONFLICT (id) DO NOTHING: redelivery is a no-op at
// the database, and "at-least-once transport" becomes "exactly once in effect".
//
// This is a delivery-path duplicate of one INSERT, not a fork of the audit
// store: the audit WRITE API every handler calls is untouched, and the delivered
// rows carry the same column set, so a reader cannot tell which writer produced
// them.
//
// # Why it PROBES the destination instead of assuming a schema version
//
// This is the lesson terraform-registry-backend learned the expensive way, and
// the reason it is ported rather than simplified away. identity/store's
// CreateAuditLog writes `actor_email` unconditionally, but that column is added
// by identity migration 000007 to `identity.audit_logs` only. In registry's
// DEFAULT topology `audit_logs` resolves to its own `public.audit_logs`, which
// has never had the column — so every audit write there fails with 42703
// (undefined_column) out of the box. That is registry #864, still open.
//
// A faithful outbox is at its most dangerous in exactly that situation: it would
// retry into a wall forever and turn a per-request failure into a permanently
// undelivered backlog. So the sink asks the CONNECTION which columns the table
// it is about to write actually has, and inserts the intersection. Under issue
// #206 that reasoning gets stronger, not weaker: audit_logs becomes per-app, so
// two apps' destinations are two different shapes by design and a shared sink
// cannot assume either.
package auditoutbox

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/lib/pq"
)

// ErrOutboxShape is the sentinel an outbox-table shape failure wraps.
var ErrOutboxShape = errors.New("identity/auditoutbox: outbox table")

// ErrDestinationShape is the sentinel a destination-table shape failure wraps.
// It surfaces through Deliver, so a destination that cannot hold an audit
// record leaves the intent in the backlog rather than losing it.
var ErrDestinationShape = errors.New("identity/auditoutbox: destination table")

// Sink is the durable destination for a delivered intent.
//
// Deliver MUST be idempotent: the relay may call it more than once for the same
// EventID, and must be able to do so without producing a second record.
type Sink interface {
	Deliver(ctx context.Context, intent Intent) error
}

// destinationColumn maps one Intent field onto the destination column that
// carries it.
type destinationColumn struct {
	name string
	// required marks a column without which the delivered row would not be an
	// audit record at all, or would not be idempotent. Everything else is
	// written when the destination has it and dropped when it does not.
	required bool
	value    func(Intent) (interface{}, error)
}

// destinationColumns is the canonical audit-row shape, in insert order.
//
// id and action are required: id because ON CONFLICT (id) is the idempotence,
// and action because a record that does not say what happened is not a record.
// created_at is NOT required — a destination that defaults it to now() still
// produces a row, and refusing delivery over it would strand the backlog for a
// column the app can add later.
var destinationColumns = []destinationColumn{
	{name: "id", required: true, value: func(i Intent) (interface{}, error) { return i.EventID, nil }},
	{name: "user_id", value: func(i Intent) (interface{}, error) { return i.ActorUserID, nil }},
	{name: "organization_id", value: func(i Intent) (interface{}, error) { return i.OrganizationID, nil }},
	{name: "action", required: true, value: func(i Intent) (interface{}, error) { return i.Action, nil }},
	{name: "resource_type", value: func(i Intent) (interface{}, error) { return i.ResourceType, nil }},
	{name: "resource_id", value: func(i Intent) (interface{}, error) { return i.ResourceID, nil }},
	{name: "metadata", value: func(i Intent) (interface{}, error) { return marshalMetadata(i.Metadata) }},
	{name: "ip_address", value: func(i Intent) (interface{}, error) { return i.IPAddress, nil }},
	{name: "created_at", value: func(i Intent) (interface{}, error) { return i.OccurredAt, nil }},
	{name: "actor_email", value: func(i Intent) (interface{}, error) { return i.ActorEmail, nil }},
}

// TableSink writes intents into an app-owned audit table.
type TableSink struct {
	db    *sql.DB
	table table

	// The insert is derived from the destination's ACTUAL columns, probed on
	// the connection in use. Cached only on success: a probe that failed
	// transiently must not permanently narrow (or permanently break) delivery,
	// which is the one thing registry's sync.Once probe got wrong — a single
	// catalogue hiccup there silently cost actor_email for the life of the
	// process.
	mu       sync.Mutex
	stmt     string
	extract  []func(Intent) (interface{}, error)
	resolved string
}

// NewTableSink constructs a sink over the connection the app's audit table
// lives on. That may or may not be the outbox's connection: the point of the
// outbox is that they are allowed to differ.
func NewTableSink(db *sql.DB, destinationTable string) (*TableSink, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: no database handle supplied", ErrDestinationShape)
	}
	t, err := parseTable("destination table", destinationTable)
	if err != nil {
		return nil, err
	}
	return &TableSink{db: db, table: t}, nil
}

// Table returns the destination table name as it was supplied.
func (s *TableSink) Table() string {
	if s == nil {
		return ""
	}
	return s.table.String()
}

// Deliver inserts the intent as a destination row keyed by its EventID.
//
// ON CONFLICT (id) DO NOTHING is the idempotence. A redelivery after a crash, or
// a duplicate claim by a second replica, updates nothing and reports success —
// which is correct: the record the caller is asking for is already there. It
// requires id to be the destination's PRIMARY KEY or to carry a UNIQUE index;
// OutboxDDL's documentation states that as a requirement on the app's table.
func (s *TableSink) Deliver(ctx context.Context, intent Intent) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("%w: no connection configured", ErrDestinationShape)
	}
	if intent.EventID == "" {
		// Without a stable id there is no idempotence, only duplicates.
		return fmt.Errorf("%w: event id is empty", ErrIntentIncomplete)
	}

	stmt, extract, err := s.plan(ctx)
	if err != nil {
		return err
	}

	args := make([]interface{}, 0, len(extract))
	for _, f := range extract {
		v, err := f(intent)
		if err != nil {
			return err
		}
		args = append(args, v)
	}

	if _, err := s.db.ExecContext(ctx, stmt, args...); err != nil {
		// 42703 undefined_column means the destination changed shape under a
		// cached plan — an app migration that added or dropped a column while
		// this process was running. Discard the plan so the next attempt
		// re-probes and can actually succeed, instead of failing identically
		// until a restart.
		var pgErr *pq.Error
		if errors.As(err, &pgErr) && pgErr.Code == "42703" {
			s.invalidate()
		}
		return fmt.Errorf("failed to deliver audit intent %s to %s: %w", intent.EventID, s.table, err)
	}
	return nil
}

// Verify probes the destination and reports the schema-qualified name it
// resolved to, so an operator can see where audit records will actually land
// and which optional columns this deployment will carry.
func (s *TableSink) Verify(ctx context.Context) (string, error) {
	if s == nil || s.db == nil {
		return "", fmt.Errorf("%w: no connection configured", ErrDestinationShape)
	}
	if _, _, err := s.plan(ctx); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resolved, nil
}

// plan returns the cached insert, probing the destination the first time.
func (s *TableSink) plan(ctx context.Context) (string, []func(Intent) (interface{}, error), error) {
	s.mu.Lock()
	if s.stmt != "" {
		stmt, extract := s.stmt, s.extract
		s.mu.Unlock()
		return stmt, extract, nil
	}
	s.mu.Unlock()

	shape, err := describeTable(ctx, s.db, s.table)
	if err != nil {
		return "", nil, err
	}
	if !shape.exists() {
		return "", nil, fmt.Errorf("%w: %s resolves to nothing on this connection (search_path %q). "+
			"This package creates no table — the app owns it",
			ErrDestinationShape, s.table, shape.searchPath)
	}

	var names []string
	var placeholders []string
	var extract []func(Intent) (interface{}, error)
	var missing []string
	for _, column := range destinationColumns {
		if !shape.has(column.name) {
			if column.required {
				missing = append(missing, column.name)
			}
			continue
		}
		names = append(names, pq.QuoteIdentifier(column.name))
		placeholders = append(placeholders, "$"+strconv.Itoa(len(names)))
		extract = append(extract, column.value)
	}
	if len(missing) > 0 {
		return "", nil, fmt.Errorf("%w: %s is missing %v. id carries the intent's EventID and is what "+
			"makes redelivery idempotent; action is the record itself. Without them a delivered row "+
			"would be neither identifiable nor meaningful, so the intent stays in the backlog",
			ErrDestinationShape, shape.qualified, missing)
	}

	stmt := `INSERT INTO ` + s.table.sql() + ` (` + strings.Join(names, ", ") + `)
		VALUES (` + strings.Join(placeholders, ", ") + `)
		ON CONFLICT (id) DO NOTHING`

	s.mu.Lock()
	s.stmt, s.extract, s.resolved = stmt, extract, shape.qualified
	s.mu.Unlock()
	return stmt, extract, nil
}

// invalidate discards the cached plan so the next delivery re-probes.
func (s *TableSink) invalidate() {
	s.mu.Lock()
	s.stmt, s.extract = "", nil
	s.mu.Unlock()
}

// tableShape is one table's resolved identity and column set.
type tableShape struct {
	qualified  string
	searchPath string
	columns    map[string]struct{}
}

func (s tableShape) exists() bool { return s.qualified != "" }

func (s tableShape) has(column string) bool {
	_, ok := s.columns[column]
	return ok
}

// describeTableQuery resolves the name and reads its columns in one round trip.
//
// to_regclass respects the connection's search_path, so the answer is about the
// table that will actually be written — not about a schema name guessed from
// configuration. The name is a BIND PARAMETER: nothing about the resolution is
// string-built.
const describeTableQuery = `
SELECT n.nspname,
       a.attname
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
WHERE c.oid = to_regclass($1)`

// describeTable reads where a table resolves and which columns it has.
//
// A probe FAILURE is an error, never a default. This package has no narrower
// statement it could safely fall back to, and guessing a shape is how a
// deployment discovers its audit trail was silently truncated.
func describeTable(ctx context.Context, db *sql.DB, t table) (tableShape, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return tableShape{}, fmt.Errorf("failed to acquire a connection to describe %s: %w", t, err)
	}
	defer func() { _ = conn.Close() }()

	shape := tableShape{columns: map[string]struct{}{}}
	var searchPath sql.NullString
	if err := conn.QueryRowContext(ctx, `SELECT current_setting('search_path', true)`).Scan(&searchPath); err != nil {
		return tableShape{}, fmt.Errorf("failed to read search_path while describing %s: %w", t, err)
	}
	shape.searchPath = searchPath.String

	rows, err := conn.QueryContext(ctx, describeTableQuery, t.String())
	if err != nil {
		return tableShape{}, fmt.Errorf("failed to describe %s: %w", t, err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var nspname string
		var attname sql.NullString
		if err := rows.Scan(&nspname, &attname); err != nil {
			return tableShape{}, fmt.Errorf("failed to describe %s: %w", t, err)
		}
		shape.qualified = nspname + "." + t.name
		if attname.Valid {
			shape.columns[attname.String] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return tableShape{}, fmt.Errorf("failed to describe %s: %w", t, err)
	}
	return shape, nil
}
