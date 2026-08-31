// schema_routing.go answers the one question this module could not previously
// answer about its own data layer: WHICH PHYSICAL TABLE does an unqualified
// query hit?
//
// The migrations here create every table schema-qualified (`identity.users`).
// The repositories in identity/store address every table UNQUALIFIED
// (`FROM users`). That is deliberate and load-bearing — it is what lets one
// repository serve both routings, and both are in production use:
//
//	search_path = identity,public   → the shared identity schema
//	search_path = "$user", public   → the consuming app's own tables
//
// Qualifying the queries would delete the second routing, which is the shipped
// DEFAULT of one of the two consuming applications. So the schema cannot be
// pinned in the SQL; it is chosen by the connection, and until now nothing
// checked that the connection chose what the operator meant.
//
// The failure that check exists to prevent is not "relation does not exist".
// Both consuming applications have identity-SHAPED tables of their own
// (`public.users`, `public.organizations`, `public.api_keys`,
// `public.audit_logs`, …) sitting in the same database as `identity.*`. A
// search_path that names the wrong one therefore routes authentication reads
// and provisioning writes to the legacy tables and SUCCEEDS: same names,
// compatible-enough columns, no error, and a split-brain identity store where a
// user removed from one set is still live in the other. There is no read that
// fails and no log line that fires. The two settings are also independent knobs
// in at least one consumer — migrations on, search_path off is a reachable
// configuration, and it is exactly the dangerous one.
//
// VerifySchemaRouting turns that into a startup failure. It is a handful of
// catalogue lookups on one borrowed connection, run once, and it converts a
// silent misroute into a process that refuses to serve.
//
// It takes the schema as a PARAMETER rather than assuming `identity`, because
// the module genuinely supports both routings and only the consumer knows which
// one it configured. An assumption here would be the same class of defect one
// level up.
package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// SchemaName is the Postgres schema this module's migrations create and
// migrate. A consumer that wants the shared identity store puts this schema
// first in its connection's search_path and passes it to VerifySchemaRouting;
// exporting it keeps that from being a third hand-copied literal.
const SchemaName = identitySchemaName

// repositoryTables is every table identity/store's repositories name in SQL,
// unqualified, sorted.
//
// It is not "every table the migrations create": identity.system_settings and
// identity.org_quotas are created here but have no accessor in this module (each
// app queries them from its own data layer, on its own connection), so this
// module cannot say which schema is right for them. It is also not "every table
// the module's SQL mentions": identity/notify's notification_channels is owned
// and created by the consuming app, lives wherever that app put it, and is
// asserted separately by notify.VerifyChannelTable.
//
// TestRepositoryTablesMatchesTheSQLTheModuleEmits keeps this list equal to the
// tables identity/store actually addresses, in both directions, so neither a new
// table nor a removed one can leave the assertion quietly incomplete.
var repositoryTables = []string{
	"api_keys",
	"audit_logs",
	"notify_dedup_claims",
	"oidc_config",
	"organization_members",
	"organizations",
	"revoked_tokens",
	"role_templates",
	"users",
}

// RepositoryTables returns the unqualified table names identity/store's
// repositories address, sorted. The returned slice is a copy: a caller that
// appends to it cannot shrink what VerifySchemaRouting checks.
func RepositoryTables() []string {
	out := make([]string, len(repositoryTables))
	copy(out, repositoryTables)
	return out
}

// TableRouting records where one unqualified table name resolves on a
// connection.
type TableRouting struct {
	// Table is the unqualified name, exactly as the module's SQL writes it.
	Table string
	// Schema is the schema the name resolved to, or "" when it resolved to
	// nothing on this connection.
	Schema string
	// Kind is the resolved relation's pg_class.relkind ("r" ordinary table,
	// "p" partitioned, "v" view, "m" materialised view, "f" foreign table,
	// "i" index, "S" sequence, …), or "" when nothing resolved. It is
	// reported because to_regclass resolves ANY relation: an index or a
	// sequence that happens to carry a table's name resolves too.
	Kind string
}

// Qualified returns the schema-qualified name the table resolved to, or "" when
// it resolved to nothing.
func (r TableRouting) Qualified() string {
	if r.Schema == "" {
		return ""
	}
	return r.Schema + "." + r.Table
}

// Routing is where one connection resolves a set of unqualified table names,
// together with the search_path that decided it.
type Routing struct {
	// SearchPath is the connection's search_path setting, as reported by
	// current_setting. It is captured on the SAME connection the names were
	// resolved on, so it explains the resolution rather than describing some
	// other connection in the pool.
	SearchPath string
	// Tables holds one entry per requested name, sorted by name.
	Tables []TableRouting
}

// ErrSchemaRouting is the sentinel every routing failure wraps, so a consumer
// can distinguish "this pool is pointed at the wrong tables" from a transport
// error and refuse to start rather than retrying.
var ErrSchemaRouting = errors.New("identity: schema routing")

// resolveRoutingQuery resolves each requested name the way the repositories'
// own SQL will: through to_regclass, which applies the connection's search_path.
//
// LEFT JOIN, not JOIN: a name that resolves to nothing must come back as a row
// with an empty schema, because "no such table" is a routing failure to report,
// not a row to drop. quote_ident keeps a name that needs quoting from being
// parsed as a qualified reference by to_regclass.
const resolveRoutingQuery = `
SELECT w.name,
       COALESCE(n.nspname, ''),
       COALESCE(c.relkind::text, '')
FROM unnest($1::text[]) AS w(name)
LEFT JOIN pg_catalog.pg_class c ON c.oid = to_regclass(quote_ident(w.name))
LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
ORDER BY w.name`

// ResolveRouting reports where each of tables resolves on a connection borrowed
// from db. With no tables it resolves RepositoryTables().
//
// It is the observability half of this file: a consumer can log the result at
// startup and see, in one line, which physical tables its identity layer is
// about to read and write. VerifySchemaRouting is the assertion half.
//
// The resolution and the search_path reading share ONE connection, so the
// reported search_path is the one that produced the reported schemas. That is a
// statement about that connection: search_path normally comes from the DSN or a
// role default and so is uniform across a pool, but a consumer that issues `SET
// search_path` on individual connections has left the pool inhomogeneous and no
// single-connection check can speak for it.
func ResolveRouting(ctx context.Context, db *sql.DB, tables ...string) (Routing, error) {
	if db == nil {
		return Routing{}, fmt.Errorf("%w: no database handle supplied", ErrSchemaRouting)
	}
	if len(tables) == 0 {
		tables = repositoryTables
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return Routing{}, fmt.Errorf("%w: failed to acquire a connection: %w", ErrSchemaRouting, err)
	}
	defer func() { _ = conn.Close() }()

	var searchPath sql.NullString
	if err := conn.QueryRowContext(ctx, `SELECT current_setting('search_path', true)`).Scan(&searchPath); err != nil {
		return Routing{}, fmt.Errorf("%w: failed to read search_path: %w", ErrSchemaRouting, err)
	}

	rows, err := conn.QueryContext(ctx, resolveRoutingQuery, tables)
	if err != nil {
		return Routing{}, fmt.Errorf("%w: failed to resolve table names: %w", ErrSchemaRouting, err)
	}
	defer func() { _ = rows.Close() }()

	out := Routing{SearchPath: searchPath.String}
	for rows.Next() {
		var r TableRouting
		if err := rows.Scan(&r.Table, &r.Schema, &r.Kind); err != nil {
			return Routing{}, fmt.Errorf("%w: failed to read resolved table names: %w", ErrSchemaRouting, err)
		}
		out.Tables = append(out.Tables, r)
	}
	if err := rows.Err(); err != nil {
		return Routing{}, fmt.Errorf("%w: failed to read resolved table names: %w", ErrSchemaRouting, err)
	}
	if len(out.Tables) != len(tables) {
		return Routing{}, fmt.Errorf("%w: asked for %d table name(s) and got %d back; "+
			"the catalogue query did not return one row per name",
			ErrSchemaRouting, len(tables), len(out.Tables))
	}
	return out, nil
}

// tableKinds are the pg_class.relkind values a repository can read and write
// through. Views and foreign tables are included because a consumer may
// legitimately front the real tables with one; indexes, sequences, composite
// types and TOAST tables are not, and a name that resolves to one of those is
// the search_path finding something that merely shares a table's name.
var tableKinds = map[string]string{
	"r": "ordinary table",
	"p": "partitioned table",
	"v": "view",
	"m": "materialised view",
	"f": "foreign table",
}

// VerifySchemaRouting asserts that every table identity/store's repositories
// address resolves, on db's connections, to a table in schema.
//
// Call it ONCE at startup, on the SAME *sql.DB the repositories are constructed
// over — not on the migration pool, which may legitimately differ (the
// migrations are schema-qualified and do not care about search_path, so a
// consumer that migrates on a plain connection is correct to do so). Pass the
// schema the deployment intends:
//
//	// Shared identity schema (connection carries search_path=identity,public).
//	if err := identity.VerifySchemaRouting(ctx, identityDB, identity.SchemaName); err != nil {
//	    return err // refuse to serve rather than read the wrong users table
//	}
//
//	// App-owned identity tables (plain connection, no shared schema).
//	if err := identity.VerifySchemaRouting(ctx, identityDB, "public"); err != nil {
//	    return err
//	}
//
// Both calls are worth making: the assertion's value is that the deployment
// STATES which routing it means, so the two configuration knobs that select it
// can no longer disagree in silence.
//
// The returned error wraps ErrSchemaRouting and names every table that resolved
// somewhere other than schema, what it resolved to instead, and the search_path
// that decided it.
func VerifySchemaRouting(ctx context.Context, db *sql.DB, schema string) error {
	schema = strings.TrimSpace(schema)
	if schema == "" {
		return fmt.Errorf("%w: no schema named; pass the schema the deployment intends "+
			"(identity.SchemaName for the shared store, or the app's own schema)", ErrSchemaRouting)
	}

	routing, err := ResolveRouting(ctx, db)
	if err != nil {
		return err
	}

	var problems []string
	for _, r := range routing.Tables {
		switch {
		case r.Schema == "":
			problems = append(problems, fmt.Sprintf(
				"%s resolves to nothing (expected %s.%s)", r.Table, schema, r.Table))
		case r.Schema != schema:
			problems = append(problems, fmt.Sprintf(
				"%s resolves to %s, not %s.%s", r.Table, r.Qualified(), schema, r.Table))
		case tableKinds[r.Kind] == "":
			problems = append(problems, fmt.Sprintf(
				"%s resolves to %s, which is not a table a repository can read or write "+
					"(pg_class.relkind %q)", r.Table, r.Qualified(), r.Kind))
		}
	}
	if len(problems) == 0 {
		return nil
	}

	return fmt.Errorf("%w: this module's repositories address tables unqualified, so the "+
		"connection's search_path (%q) decides which physical tables they read and write, "+
		"and %d of %d do not resolve to schema %q:\n  - %s\n"+
		"Reads and writes against the wrong identity tables SUCCEED — the names and columns "+
		"line up — so this is checked here rather than discovered as a split-brain identity "+
		"store. Fix the connection's search_path, or pass the schema this deployment actually "+
		"intends",
		ErrSchemaRouting, routing.SearchPath, len(problems), len(routing.Tables), schema,
		strings.Join(problems, "\n  - "))
}
