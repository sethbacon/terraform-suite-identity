// schema.go makes the notification_channels contract executable.
//
// ChannelRepository reads and writes a table this module does NOT create.
// Until now the contract for it was a sentence in a doc comment that each
// consuming app re-implemented by hand — and they drifted exactly as prose
// contracts do: one app shipped `encrypted_target BYTEA` and `events TEXT[]`
// against a DAO that binds base64 text and JSONB, and only found out when a
// delivery attempt failed a scan. That is the failure the migration mechanism
// exists to prevent, so this file supplies the two things a migration would
// have: ONE canonical definition (ChannelTableDDL, executed by this module's own
// tests, so it cannot drift from the DAO), and a startup assertion
// (VerifyChannelTable) that fails loudly when the app's table does not match.
//
// What this file deliberately does NOT do is ship a migration.
//
// Both consuming applications already hold live notification_channels data, in
// `public`, created by their own migration sets, read through a pool whose
// search_path is the default `"$user", public`. A migration here would create a
// SECOND, empty `identity.notification_channels`, and every connection that puts
// `identity` first — which is precisely the connection a consumer would move
// this repository onto once the module claimed ownership — would silently
// re-point from the populated table to the empty one. Same query, no error, no
// rows: a data-loss-shaped outage with green tests. Rows cannot be moved from
// here either; that is a consumer deploy step, ordered against a consumer's own
// migrations, on a database this module does not own.
//
// So the table stays app-owned, and what this module owns is the SHAPE and the
// assertion that the shape is real. VerifyChannelTable also reports the
// schema-qualified name it resolved to, so an operator can see where deliveries
// are actually being recorded instead of assuming.
package notify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ChannelTable is the unqualified table name every ChannelRepository statement
// addresses. Which physical table that reaches is decided by the connection's
// search_path — see VerifyChannelTable.
const ChannelTable = "notification_channels"

// ChannelTableDDL is the canonical definition of the notification_channels
// table ChannelRepository requires. It is the contract this package used to
// state in prose.
//
// Apply it from the CONSUMING APP's own migration set, not from this module:
// the app owns the table, owns the schema it lives in, and owns any data
// already in it. The statement is deliberately unqualified, so the migration
// connection's search_path places it — the same rule that decides where the
// repository will later look for it.
//
// The unique index on name is included because both shipped consumers
// independently arrived at it (a channel list with two identically named
// destinations is an admin-UI defect), not because any statement in this
// package depends on it. VerifyChannelTable accordingly does not assert it.
//
// TestChannelTableDDLDeclaresExactlyTheColumnsTheDAORequires keeps this
// statement and channelColumns from drifting apart.
const ChannelTableDDL = `CREATE TABLE IF NOT EXISTS notification_channels (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name             TEXT        NOT NULL,
    type             TEXT        NOT NULL,                    -- webhook | slack | teams | email
    encrypted_target TEXT        NOT NULL,                    -- sealed destination URL or recipient list
    events           JSONB       NOT NULL DEFAULT '[]'::jsonb, -- subscribed events; empty = all
    enabled          BOOLEAN     NOT NULL DEFAULT true,
    last_status      TEXT,                                    -- sent | failed
    last_error       TEXT,
    last_sent_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_notification_channels_name
    ON notification_channels (name);`

// ErrChannelTable is the sentinel every notification_channels schema failure
// wraps.
var ErrChannelTable = errors.New("identity/notify: notification_channels")

// columnRequirement is what one column must be for ChannelRepository's
// statements to work. Each entry states the statement that requires it, because
// a shape assertion nobody can justify is one somebody will loosen.
type columnRequirement struct {
	// types are the accepted format_type outputs, with any length modifier
	// stripped. A requirement lists every type the DAO behaves identically
	// on: asserting more than behaviour needs would fail a deployment that
	// works, which is its own kind of false alarm.
	types []string
	// notNull is true when the DAO scans the column into a non-pointer Go
	// value, so a NULL is a scan failure at delivery time rather than a
	// value.
	notNull bool
	// why names the statement or scan that imposes the requirement.
	why string
}

// channelColumnRequirements is the executable form of this package's schema
// contract, keyed by column name.
var channelColumnRequirements = map[string]columnRequirement{
	"id": {
		types:   []string{"uuid", "text", "character varying", "character"},
		notNull: true,
		why:     "scanned into NotificationChannel.ID (string) and bound by every by-id statement",
	},
	"name": {
		types:   []string{"text", "character varying", "character"},
		notNull: true,
		why:     "scanned into NotificationChannel.Name (string)",
	},
	"type": {
		types:   []string{"text", "character varying", "character"},
		notNull: true,
		why:     "scanned into NotificationChannel.Type (string); selects the delivery transport",
	},
	"encrypted_target": {
		types:   []string{"text", "character varying", "character"},
		notNull: true,
		why:     "scanned into NotificationChannel.EncryptedTarget (string); holds the sealed target as text, so a bytea column fails the scan",
	},
	"events": {
		types:   []string{"jsonb"},
		notNull: true,
		why:     "ListEnabledForEvent applies jsonb_array_length(events) and events @> to_jsonb($1::text); neither operator exists for json or text[]",
	},
	"enabled": {
		types:   []string{"boolean"},
		notNull: true,
		why:     "ListEnabledForEvent's WHERE enabled predicate, scanned into NotificationChannel.Enabled (bool)",
	},
	"last_status": {
		types: []string{"text", "character varying", "character"},
		why:   "scanned into sql.NullString, so NULL is a value here rather than a failure",
	},
	"last_error": {
		types: []string{"text", "character varying", "character"},
		why:   "scanned into sql.NullString, so NULL is a value here rather than a failure",
	},
	"last_sent_at": {
		types: []string{"timestamp with time zone"},
		why:   "RecordDelivery binds a time.Time; timestamp without time zone silently discards the offset",
	},
	"created_at": {
		types:   []string{"timestamp with time zone"},
		notNull: true,
		why:     "List orders by it and it is scanned into a non-pointer time.Time; timestamp without time zone silently discards the offset",
	},
	"updated_at": {
		types:   []string{"timestamp with time zone"},
		notNull: true,
		why:     "stamped by Update and RecordDelivery and scanned into a non-pointer time.Time; timestamp without time zone silently discards the offset",
	},
}

// channelSchemaQuery reads the resolved table's schema and column shape in one
// round trip.
//
// It resolves through to_regclass, exactly as ChannelRepository's own
// unqualified statements will, and then reads the catalogue by the resolved
// OID — so the shape reported is unambiguously the shape of the table the
// repository is about to use, not of some same-named table elsewhere. No rows
// means the name resolved to nothing.
const channelSchemaQuery = `
SELECT n.nspname,
       a.attname,
       format_type(a.atttypid, a.atttypmod),
       a.attnotnull
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
WHERE c.oid = to_regclass(quote_ident($1))
ORDER BY a.attnum`

// VerifyChannelTable asserts that the notification_channels table
// ChannelRepository will address exists on db's connections and has the columns,
// types and nullability its statements require. It returns the schema-qualified
// name the unqualified table name resolved to.
//
// Call it ONCE at startup, on the SAME *sql.DB the ChannelRepository is
// constructed over, and log the name it returns. The returned name is the point:
// this table is app-owned and this module does not know which schema it should
// be in, so the assertion reports where deliveries will actually be read and
// recorded rather than assuming. A deployment that changes a search_path, or
// acquires a second notification_channels in another schema, sees the change in
// that line instead of discovering it as an empty channel list.
//
// Errors wrap ErrChannelTable and name every column that is missing or wrong,
// together with the statement that requires it.
func VerifyChannelTable(ctx context.Context, db *sql.DB) (string, error) {
	if db == nil {
		return "", fmt.Errorf("%w: no database handle supplied", ErrChannelTable)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: failed to acquire a connection: %w", ErrChannelTable, err)
	}
	defer func() { _ = conn.Close() }()

	var searchPath sql.NullString
	if err := conn.QueryRowContext(ctx, `SELECT current_setting('search_path', true)`).Scan(&searchPath); err != nil {
		return "", fmt.Errorf("%w: failed to read search_path: %w", ErrChannelTable, err)
	}

	rows, err := conn.QueryContext(ctx, channelSchemaQuery, ChannelTable)
	if err != nil {
		return "", fmt.Errorf("%w: failed to read the table definition: %w", ErrChannelTable, err)
	}
	defer func() { _ = rows.Close() }()

	type actualColumn struct {
		dataType string
		notNull  bool
	}
	schema := ""
	actual := map[string]actualColumn{}
	for rows.Next() {
		var nspname, attname, dataType string
		var notNull bool
		if err := rows.Scan(&nspname, &attname, &dataType, &notNull); err != nil {
			return "", fmt.Errorf("%w: failed to read the table definition: %w", ErrChannelTable, err)
		}
		schema = nspname
		actual[attname] = actualColumn{dataType: dataType, notNull: notNull}
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("%w: failed to read the table definition: %w", ErrChannelTable, err)
	}

	if schema == "" {
		return "", fmt.Errorf("%w: %s resolves to nothing on this connection (search_path %q). "+
			"This module does not create the table — the consuming app owns it. Apply "+
			"notify.ChannelTableDDL from the app's own migration set, in the schema this "+
			"connection resolves to",
			ErrChannelTable, ChannelTable, searchPath.String)
	}
	qualified := schema + "." + ChannelTable

	var problems []string
	for _, name := range sortedRequirementNames() {
		req := channelColumnRequirements[name]
		got, ok := actual[name]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s is missing (%s)", name, req.why))
			continue
		}
		if !typeSatisfies(got.dataType, req.types) {
			problems = append(problems, fmt.Sprintf("%s is %s, want %s (%s)",
				name, got.dataType, strings.Join(req.types, " or "), req.why))
		}
		if req.notNull && !got.notNull {
			problems = append(problems, fmt.Sprintf("%s is nullable, want NOT NULL (%s)",
				name, req.why))
		}
	}
	if len(problems) == 0 {
		return qualified, nil
	}

	return qualified, fmt.Errorf("%w: %s does not match the shape this package's statements "+
		"require, so notification delivery would fail at send time rather than here:\n  - %s\n"+
		"notify.ChannelTableDDL is the canonical definition; reconcile the app's migration "+
		"set against it",
		ErrChannelTable, qualified, strings.Join(problems, "\n  - "))
}

// sortedRequirementNames returns the required column names in a stable order, so
// the error lists every problem the same way on every run.
func sortedRequirementNames() []string {
	names := make([]string, 0, len(channelColumnRequirements))
	for name := range channelColumnRequirements {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// typeSatisfies reports whether a format_type output is one of the accepted
// types, ignoring any length modifier — character varying(255) and text are the
// same thing to every statement in this package, and failing a deployment over
// that difference would be an assertion nobody keeps.
func typeSatisfies(dataType string, accepted []string) bool {
	base := dataType
	if i := strings.IndexByte(base, '('); i >= 0 {
		base = strings.TrimSpace(base[:i])
	}
	for _, want := range accepted {
		if base == want {
			return true
		}
	}
	return false
}
