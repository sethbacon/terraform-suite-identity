// schema.go makes the carrier's table contract executable.
//
// Carrier reads and writes a table this module does NOT create, in a schema this
// module does not choose. That is not an oversight — it is the identity model
// this package exists to serve. "Who administers this application" is a per-app
// authorization fact, so the row belongs in the app's own schema alongside its
// role definitions and its audit log, and two applications sharing one identity
// store keep two independent administrator populations. A migration shipped from
// here would create a single shared table and quietly make one application's
// administrators the other's.
//
// The cost of app-owned DDL is a contract stated in prose that each app
// re-implements by hand and drifts from. This module already paid that cost once
// with notification_channels (identity/notify/schema.go: one app shipped
// `encrypted_target BYTEA` against a DAO binding text and found out at delivery
// time). So this file supplies the same two things a migration would have: ONE
// canonical definition (TableDDL, executed by this package's own integration
// tests, so it cannot drift from the statements), and a startup assertion
// (Carrier.VerifyTable) that fails loudly when the app's table does not match.
//
// # No foreign keys, and it is deliberate
//
// The obvious definition is `user_id UUID PRIMARY KEY REFERENCES users(id) ON
// DELETE CASCADE` with `granted_by UUID REFERENCES users(id) ON DELETE SET
// NULL`. Those constraints cannot hold across the topologies this module
// supports. The carrier is created by the APPLICATION, on the application's own
// connection, while identity data may live:
//
//  1. in the same schema as the app's tables — an FK would work
//  2. in a shared `identity` schema the app's connection also reaches — an FK
//     would work only until identity moved
//  3. in a SEPARATE DATABASE — Postgres has no cross-database foreign keys at
//     all, so the constraint is not expressible
//
// Since (3) is a supported deployment, the DDL cannot carry the constraint in
// any deployment without making the table's definition depend on a topology
// choice made elsewhere. Both consuming applications reached this same
// conclusion independently for their own per-user auth tables.
//
// What the foreign keys would have bought is bounded and is paid for elsewhere.
// User ids are UUIDs and are never reused, so a row left behind by a deleted user
// grants nothing to anybody: every elevation path loads the principal first, and
// an unresolvable grant elevates nobody. What it DOES do is sit in the carrier
// looking like an administrator, which is why the floor counts only grants that
// still resolve (RequireAnotherExercisableAdmin) and why sweeping orphans belongs
// with the rest of the app's credential lifecycle — the cross-connection cleanup
// an FK could not have done either.
//
// # Why this package is outside the schema-routing contract
//
// identity.VerifySchemaRouting and the routing class test cover the tables
// identity/store and identity/notify name in SQL, because those resolve through
// search_path to tables this module's migrations create. The carrier resolves to
// a table this module neither creates nor names — the application supplies the
// name — so it is deliberately not in RepositoryTables(). VerifyTable is its
// equivalent: it reports the schema-qualified name the configured name actually
// resolved to, so an operator can see where administrator grants are being read
// from rather than assuming.
package platformadmin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrTableShape is the sentinel every carrier-table schema failure wraps.
var ErrTableShape = errors.New("platformadmin: carrier table")

// TableDDL returns the canonical definition of the carrier table, for the
// CONSUMING APP's own migration set.
//
// table is named the same way as for New — "platform_admins" to let the
// migration connection's search_path place it, or "registry.platform_admins" to
// pin the schema. It is validated identically, so a name New would refuse
// cannot be created here either.
//
// The statement carries no foreign keys; see this file's package comment for
// why, and reproduce that reasoning in the app's migration rather than
// "improving" it back in.
//
// user_id is the PRIMARY KEY and that is load-bearing, not decorative: Grant
// uses ON CONFLICT (user_id) DO NOTHING to make a re-grant preserve the original
// provenance, and ON CONFLICT requires a unique index on exactly that column.
// A table created without it fails at grant time, which is why VerifyTable
// checks for the index and not merely for the columns.
func TableDDL(table string) (string, error) {
	quoted, err := quoteTable(table)
	if err != nil {
		return "", err
	}
	// #nosec G202 -- quoted is a validated, pq-quoted identifier from
	// quoteTable; a DDL statement's table name cannot be a bind parameter.
	return `CREATE TABLE IF NOT EXISTS ` + quoted + ` (
    user_id     UUID        PRIMARY KEY,
    granted_by  UUID,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    note        TEXT
);`, nil
}

// columnRequirement is what one column must be for the carrier's statements to
// work. Each entry states the statement that requires it, because a shape
// assertion nobody can justify is one somebody will loosen.
type columnRequirement struct {
	// types are the accepted format_type outputs, with any length modifier
	// stripped. A requirement lists every type the statements behave
	// identically on: asserting more than behaviour needs would fail a
	// deployment that works.
	types []string
	// notNull is true when a NULL would be scanned into a non-pointer Go
	// value, so it is a scan failure at read time rather than a value.
	notNull bool
	// why names the statement or scan that imposes the requirement.
	why string
}

// columnRequirements is the executable form of the carrier's schema contract.
var columnRequirements = map[string]columnRequirement{
	"user_id": {
		types:   []string{"uuid", "text", "character varying", "character"},
		notNull: true,
		why:     "bound by every statement and scanned into Grant.UserID (string)",
	},
	"granted_by": {
		types: []string{"uuid", "text", "character varying", "character"},
		why:   "scanned into Grant.GrantedBy (*string); NULL is a value here — a grant with no attributable actor",
	},
	"granted_at": {
		types:   []string{"timestamp with time zone"},
		notNull: true,
		why:     "List and the locking read order by it and it is scanned into a non-pointer time.Time; timestamp without time zone silently discards the offset",
	},
	"note": {
		types: []string{"text", "character varying", "character"},
		why:   "scanned into Grant.Note (*string); NULL is a value here",
	},
}

// tableShapeQuery reads the resolved table's schema and column shape in one
// round trip, resolving through to_regclass exactly as the carrier's own
// statements will. No rows means the name resolved to nothing.
const tableShapeQuery = `
SELECT n.nspname,
       a.attname,
       format_type(a.atttypid, a.atttypmod),
       a.attnotnull
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
WHERE c.oid = to_regclass($1)
ORDER BY a.attnum`

// uniqueUserIDQuery asks whether the resolved table has a unique index on
// exactly user_id — the index ON CONFLICT (user_id) requires.
//
// Partial (indpred) and invalid indexes are excluded because ON CONFLICT will
// not use them either: a partial unique index is not an arbiter for an
// unqualified conflict target, so accepting one here would report a table as
// sound and let Grant fail in production instead.
const uniqueUserIDQuery = `
SELECT EXISTS (
  SELECT 1
    FROM pg_catalog.pg_index i
    JOIN pg_catalog.pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
   WHERE i.indrelid = to_regclass($1)
     AND i.indisunique
     AND i.indisvalid
     AND i.indpred IS NULL
     AND i.indnatts = 1
     AND a.attname = 'user_id')`

// VerifyTable asserts that the carrier table exists on db's connections and has
// the columns, types, nullability and unique index the carrier's statements
// require. It returns the schema-qualified name the configured name resolved to.
//
// Call it ONCE at startup, on the SAME *sql.DB the Carrier was constructed over,
// and log the name it returns. The returned name is the point: this table is
// app-owned and this module does not know which schema it should be in, so the
// assertion reports where administrator grants will actually be read and written
// rather than assuming. A deployment that changes a search_path, or acquires a
// second platform_admins in another schema, sees the change in that line instead
// of discovering it as an empty administrator list.
//
// Errors wrap ErrTableShape and name every column that is missing or wrong,
// together with the statement that requires it.
func (c *Carrier) VerifyTable(ctx context.Context) (string, error) {
	if c == nil || c.db == nil {
		return "", fmt.Errorf("%w: VerifyTable on an unconstructed carrier", ErrNotConfigured)
	}

	conn, err := c.db.Conn(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: failed to acquire a connection: %w", ErrTableShape, err)
	}
	defer func() { _ = conn.Close() }()

	var searchPath sql.NullString
	if err := conn.QueryRowContext(ctx, `SELECT current_setting('search_path', true)`).Scan(&searchPath); err != nil {
		return "", fmt.Errorf("%w: failed to read search_path: %w", ErrTableShape, err)
	}

	rows, err := conn.QueryContext(ctx, tableShapeQuery, c.table)
	if err != nil {
		return "", fmt.Errorf("%w: failed to read the table definition: %w", ErrTableShape, err)
	}
	defer func() { _ = rows.Close() }()

	schema := ""
	actual := map[string]actualColumn{}
	for rows.Next() {
		var nspname, attname, dataType string
		var notNull bool
		if err := rows.Scan(&nspname, &attname, &dataType, &notNull); err != nil {
			return "", fmt.Errorf("%w: failed to read the table definition: %w", ErrTableShape, err)
		}
		schema = nspname
		actual[attname] = actualColumn{dataType: dataType, notNull: notNull}
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("%w: failed to read the table definition: %w", ErrTableShape, err)
	}

	if schema == "" {
		return "", fmt.Errorf("%w: %s resolves to nothing on this connection (search_path %q). "+
			"This module does not create the table — the consuming app owns it. Apply "+
			"platformadmin.TableDDL from the app's own migration set, in the schema this "+
			"connection resolves to",
			ErrTableShape, c.table, searchPath.String)
	}
	qualified := schema + "." + strings.Trim(lastPart(c.table), `"`)

	problems := shapeProblems(actual)

	var hasUnique bool
	if err := conn.QueryRowContext(ctx, uniqueUserIDQuery, c.table).Scan(&hasUnique); err != nil {
		return qualified, fmt.Errorf("%w: failed to read the table's indexes: %w", ErrTableShape, err)
	}
	if !hasUnique {
		problems = append(problems, "there is no non-partial unique index on exactly (user_id) "+
			"(Grant's ON CONFLICT (user_id) DO NOTHING has no arbiter without one, so every grant "+
			"would fail; declare user_id as the PRIMARY KEY)")
	}

	if len(problems) == 0 {
		return qualified, nil
	}
	return qualified, fmt.Errorf("%w: %s does not match the shape this package's statements "+
		"require, so administrator grants would fail at write time rather than here:\n  - %s\n"+
		"platformadmin.TableDDL is the canonical definition; reconcile the app's migration "+
		"set against it",
		ErrTableShape, qualified, strings.Join(problems, "\n  - "))
}

// actualColumn is one column as the catalogue reports it.
type actualColumn struct {
	dataType string
	notNull  bool
}

// shapeProblems lists every column requirement the actual table fails, in a
// stable order so the error reads the same way on every run.
func shapeProblems(actual map[string]actualColumn) []string {
	names := make([]string, 0, len(columnRequirements))
	for name := range columnRequirements {
		names = append(names, name)
	}
	sort.Strings(names)

	var problems []string
	for _, name := range names {
		req := columnRequirements[name]
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
	return problems
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

// lastPart returns the table half of a quoted, possibly schema-qualified
// reference. Used only to render the resolved name back to the operator.
func lastPart(quoted string) string {
	if i := strings.LastIndex(quoted, `"."`); i >= 0 {
		return quoted[i+2:]
	}
	return quoted
}
