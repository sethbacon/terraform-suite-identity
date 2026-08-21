// channel_scope.go makes ChannelRepository's row-selecting statements
// OPTIONALLY tenant-scoped, for the consuming app whose notification_channels
// table carries an organization_id and only for that app.
//
// # Why this is optional when identity/store's OrgScope is mandatory
//
// store.OrgScope is a REQUIRED parameter of every scoped accessor in that
// package, and its zero value denies everything, on purpose: those accessors
// read tables THIS MODULE owns and creates, so every consumer has the
// organization_id column and a caller who has not thought about tenancy must
// get no rows rather than every tenant's rows. See org_scope.go, which argues
// that case at length.
//
// notification_channels is the one table this package reads that it does NOT
// own. schema.go explains why: both applications already hold live data in a
// table their own migrations created, so this module ships the SHAPE
// (ChannelTableDDL) and an assertion (VerifyChannelTable) instead of a
// migration. The two consumers have consequently diverged on this column, and
// legitimately so:
//
//   - terraform-state-manager added a nullable organization_id in its migration
//     000033, the first phase of partitioning its nine "partition root" tables
//     by organization. Its channels are per-tenant: encrypted_target holds a
//     capability-bearing secret (a Slack or webhook URL that anyone holding it
//     can post to), so one organization enumerating another's channels is the
//     leak the partition exists to close.
//   - terraform-registry has no such column and no plan for one. Its channels
//     are platform-level delivery destinations for module_published and
//     cve_detected events, configured by a platform admin.
//
// A predicate baked into these statements would therefore break the second
// consumer at the first query — `column "organization_id" does not exist` — for
// a boundary it has no rows to enforce. Hard-coding it is not available.
//
// # So the OPTION is optional; the SCOPE inside it is not
//
// The optionality is on ONE axis only: does this consumer's table carry the
// column at all. That is a deployment fact, it is knowable at wire-up time, and
// it is stated once per call site. Everything downstream of "yes" keeps
// store.OrgScope's fail-closed semantics unchanged — a zero OrgScope handed to
// WithOrgScope still matches nothing, reaching every organization still has to
// be spelled OrgScopeAllOrganizations(), and NULL owners are still admitted only
// by OrgScopeOrganizationsAndUnowned. This file adds no third meaning of "no
// scope"; it adds a way to say "this table has no tenant column", which is a
// different sentence.
//
// The distinction is visible at the call site, which is the property that
// matters when someone later greps for who enforces the boundary:
//
//	repo.List(ctx)                                  // no tenant column here
//	repo.List(ctx, notify.WithOrgScope(scope))      // scoped, and scope decides
//
// An absent option is not a scope that failed open. It is a statement that this
// deployment's table has nothing to scope BY — and a deployment that gets that
// wrong is caught at startup by VerifyChannelOrganizationColumn rather than by a
// query that quietly returned another tenant's channels.
//
// # Why a variadic option and not a parameter
//
// A new required parameter — even `store.OrgScope` — would not compile in
// terraform-registry, which calls these methods in its admin routes, its
// notifier and its API-key expiry job. Forcing that consumer to pass
// OrgScopeAllOrganizations() at every call site would make "reach every
// organization" the routine spelling in a codebase where it is not a decision
// anyone is making, which is precisely the greppability org_scope.go is trying
// to buy. The variadic form leaves those call sites untouched and byte-identical
// in the SQL they emit (TestUnscopedStatementsAreUnchanged pins that), and
// leaves the scoped spelling reserved for the consumer that means it.
package notify

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/sethbacon/terraform-suite-identity/identity/store"
)

// ChannelOrganizationColumn is the column a scoped statement constrains. It is
// the estate-wide spelling — the same one identity/store's own tables use and
// the one terraform-state-manager's migration 000033 added — and it is exported
// so a consumer's migration and its docs can name the column this package will
// actually address rather than a copy of the string.
const ChannelOrganizationColumn = "organization_id"

// ChannelQueryOption modifies how a ChannelRepository statement selects rows.
// The only option today is WithOrgScope.
type ChannelQueryOption func(*channelFilter)

// channelFilter is the accumulated effect of a statement's options. Its ZERO
// VALUE is the unscoped statement — the one this package has always emitted —
// so a caller that passes no options gets today's SQL, not a scope that
// silently permits everything.
type channelFilter struct {
	// scoped records that a caller asked for tenant scoping at all, which is
	// separate from what the scope then permits. Without it, the zero
	// OrgScope (which denies) would be indistinguishable from "this table has
	// no organization_id", and one of those two must produce no predicate
	// while the other must produce FALSE.
	scoped bool
	scope  store.OrgScope
}

// WithOrgScope restricts a statement to the organizations the scope permits.
//
// Pass it only against a notification_channels table that carries
// ChannelOrganizationColumn; VerifyChannelOrganizationColumn asserts that at
// startup, and calling it once is how a consumer turns "we intend to scope" into
// a checked fact rather than an assumption every query re-makes.
//
// The scope keeps every semantic identity/store gives it. In particular the ZERO
// OrgScope permits nothing, so
//
//	repo.List(ctx, notify.WithOrgScope(store.OrgScope{}))
//
// returns no rows. That is deliberate: having said the table is partitioned, a
// caller who then cannot say which partition they are in is a caller who should
// see nothing. Reaching across every organization is available, and has to be
// written down, as WithOrgScope(store.OrgScopeAllOrganizations()).
//
// A channel whose organization_id is NULL — a row written before a consumer's
// backfill ran, or one a deployment has deliberately left platform-level — is
// admitted only by a scope built with store.OrgScopeOrganizationsAndUnowned, or
// widened with store.OrgScope.WithUnowned. This package does not decide what a
// consumer's NULLs mean; org_scope.go explains why that judgement cannot be made
// centrally.
func WithOrgScope(scope store.OrgScope) ChannelQueryOption {
	return func(f *channelFilter) {
		f.scoped = true
		f.scope = scope
	}
}

// newChannelFilter folds a statement's options together.
func newChannelFilter(opts []ChannelQueryOption) channelFilter {
	var f channelFilter
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&f)
	}
	return f
}

// splice appends the tenant predicate to query, joining it with connector
// (" WHERE " for a statement that constrains nothing yet, " AND " for one that
// already has a WHERE clause), and returns the extended argument list.
//
// It is the SINGLE splice site for a tenant predicate in this package, mirroring
// identity/store's unexported andScope and for the same three reasons: "does
// this statement enforce tenancy?" stays answerable by grep, the gosec
// suppression has one home instead of one per query, and the paramIndex
// arithmetic — the part a hand-written call site gets wrong — is a property of
// the helper rather than of each caller.
//
// Callers MUST pass the argument slice as it stands at the splice point, because
// the placeholder index is derived from its length. Unlike identity/store, which
// splices the scope FIRST and then appends caller filters, this package splices
// LAST: these statements bind their arguments positionally into a SET clause and
// an id predicate that were written before this option existed, and renumbering
// them to put the scope first would change the SQL emitted on the UNSCOPED path
// — the one path that must not move.
//
// When no scope was requested the query and the arguments are returned exactly
// as they came in. Not "with a TRUE predicate": the unscoped statement has to
// remain the statement this package has always sent, down to the bytes, because
// the other consumer's tests match on it and its query plans were formed against
// it.
func (f channelFilter) splice(query, connector string, args []any) (string, []any) {
	if !f.scoped {
		return query, args
	}
	clause, scopeArgs := f.scope.SQL(ChannelOrganizationColumn, len(args)+1)
	// #nosec G202 -- clause comes from store.OrgScope.SQL: one of "TRUE", "FALSE",
	// or a fixed template over the ChannelOrganizationColumn constant and a $N
	// placeholder. Scope values travel as query arguments and are never
	// interpolated.
	return query + connector + clause, append(args, scopeArgs...)
}

// channelOrganizationRequirement is what ChannelOrganizationColumn must be for a
// scoped statement to work. It is deliberately NOT a member of
// channelColumnRequirements: that map is what VerifyChannelTable demands of
// every consumer, and this column is required of only one of them. Adding it
// there would fail terraform-registry's startup over a column it has no reason
// to hold — which is the same mistake as baking the predicate into the queries,
// just moved to boot time.
var channelOrganizationRequirement = columnRequirement{
	// Same set id accepts. terraform-state-manager's 000033 uses UUID; a
	// consumer keying organizations by text would bind an equally valid
	// argument through `= ANY($n)`.
	types: []string{"uuid", "text", "character varying", "character"},
	// notNull is deliberately unset. terraform-state-manager's partitioning
	// adds the column NULLABLE in phase one and only makes it NOT NULL in its
	// final, breaking phase, so asserting either state here would fail a
	// deployment that works — on one side during the migration, on the other
	// side after it.
	notNull: false,
	why:     "bound by WithOrgScope's tenant predicate (" + ChannelOrganizationColumn + " = ANY($n))",
}

// VerifyChannelOrganizationColumn asserts that the notification_channels table
// ChannelRepository will address carries ChannelOrganizationColumn with a type
// the tenant predicate can bind against.
//
// Call it ONCE at startup, on the SAME *sql.DB the ChannelRepository is
// constructed over, and ONLY in an application that intends to pass
// WithOrgScope. It is separate from VerifyChannelTable, rather than folded into
// it, for the reason the whole column is optional: VerifyChannelTable states
// what EVERY consumer must have, and this is not that. Keeping them apart also
// keeps VerifyChannelTable's signature stable, so adopting this capability is
// not a change any existing caller has to make.
//
// The check exists because the failure it replaces is a bad one. A consumer that
// wires WithOrgScope against a table without the column does not find out at
// wire-up; it finds out when an admin opens the channels page and Postgres
// reports `column "organization_id" does not exist`, or — worse, if the option
// were ever plumbed through a path that swallows errors — sees an empty list and
// concludes there are no channels configured. This turns that into a startup
// failure that names the migration to run, which is the same trade schema.go
// makes for the table as a whole.
//
// Errors wrap ErrChannelTable.
func VerifyChannelOrganizationColumn(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("%w: no database handle supplied", ErrChannelTable)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("%w: failed to acquire a connection: %w", ErrChannelTable, err)
	}
	defer func() { _ = conn.Close() }()

	rows, err := conn.QueryContext(ctx, channelSchemaQuery, ChannelTable)
	if err != nil {
		return fmt.Errorf("%w: failed to read the table definition: %w", ErrChannelTable, err)
	}
	defer func() { _ = rows.Close() }()

	schema := ""
	dataType := ""
	found := false
	for rows.Next() {
		var nspname, attname, format string
		var notNull bool
		if err := rows.Scan(&nspname, &attname, &format, &notNull); err != nil {
			return fmt.Errorf("%w: failed to read the table definition: %w", ErrChannelTable, err)
		}
		schema = nspname
		if attname == ChannelOrganizationColumn {
			dataType = format
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: failed to read the table definition: %w", ErrChannelTable, err)
	}

	if schema == "" {
		return fmt.Errorf("%w: %s resolves to nothing on this connection, so its columns "+
			"cannot be checked. Call VerifyChannelTable first — it reports where the table "+
			"is expected to be and why it is the consuming app that creates it",
			ErrChannelTable, ChannelTable)
	}
	qualified := schema + "." + ChannelTable

	if !found {
		return fmt.Errorf("%w: %s has no %s column, so notify.WithOrgScope cannot scope it "+
			"(%s). Add the column from the app's own migration set, or stop passing "+
			"WithOrgScope — this column is required only of applications that partition "+
			"notification channels by organization",
			ErrChannelTable, qualified, ChannelOrganizationColumn, channelOrganizationRequirement.why)
	}
	if !typeSatisfies(dataType, channelOrganizationRequirement.types) {
		return fmt.Errorf("%w: %s.%s is %s, want %s (%s)",
			ErrChannelTable, qualified, ChannelOrganizationColumn, dataType,
			strings.Join(channelOrganizationRequirement.types, " or "), channelOrganizationRequirement.why)
	}
	return nil
}
