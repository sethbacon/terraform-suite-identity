// schema_version.go states, and enforces, the MINIMUM identity migration
// version this module's own SQL requires.
//
// Every repository in identity/store addresses columns unqualified and
// unconditionally: there is no capability probe, no COALESCE-around-a-missing
// column, no version branch. That is deliberate — a library that carries
// compatibility shims for migrations it owns carries them forever — but it
// makes the migration chain a HARD PRECONDITION rather than a recommendation,
// and until now that precondition was neither written down nor checked.
//
// The failure it produces is the worst shape available. AuditRepository.
// CreateAuditLog writes audit_logs.actor_email, a column migration 000007 adds.
// Against a 000006 schema the repository constructs fine, the process starts
// fine, health checks pass, and then EVERY audited request fails with
//
//	failed to create audit log: pq: column "actor_email" of relation
//	"audit_logs" does not exist (42703)
//
// at request time, in a consumer whose own startup log had already printed
// "Database migrations completed successfully" — about its OWN migration chain,
// which is a different chain. That is not hypothetical; it took a consumer down
// (sethbacon/terraform-registry-backend#864, filed here as #203).
//
// The primitive to catch it already existed. GetMigrationVersion has been
// exported and documented as "shaped like a readiness probe" since the module's
// first release, and no consumer has ever called it — because nothing told a
// consumer what number to compare it against. What was missing was the number,
// and something that does the comparison and refuses.
//
// # Why a startup check and not a per-call check
//
// The check is one catalogue round trip on one borrowed connection. Doing it
// per call would put that round trip on the audit write path, which is the hot
// path of every mutating request in both consumers; caching it behind a
// sync.Once removes the cost but not the timing, and the timing is the actual
// defect — "first audited request" is still runtime, still after the deploy is
// live, still after health checks went green. A precondition that can only be
// discovered by violating it is not a precondition.
//
// So it runs at startup, once, alongside VerifySchemaRouting. The cost of that
// choice is honest and worth stating: a consumer that never calls it is exactly
// as exposed as before. This module cannot make a consumer call a function.
// What it can do is make the requirement a NUMBER a consumer can compare
// against, a LIST an operator can read, and a single call that turns both into
// a refusal to start — and then say so in the schema reference, which is where
// an operator goes when the identity tables are involved.
package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// RequiredSchemaVersion is the lowest identity migration version at which every
// column this module's SQL names actually exists.
//
// It is the maximum over schemaRequirements, and
// TestRequiredSchemaVersionIsTheMaximumOfTheRequirements holds it there. It is
// a const rather than a computed variable so it is greppable from a consumer's
// code review and usable in a compile-time comparison.
//
// Raising it is a compatibility event for consumers, not a mechanical bump: a
// consumer pinned to an older schema starts failing VerifySchemaVersion the
// moment it upgrades this module. That is the intended behaviour — the
// alternative is the 42703 — but it belongs in the release notes.
const RequiredSchemaVersion uint = 8

// SchemaRequirement is one column this module's SQL names that the base schema
// does not create, together with the migration that adds it.
type SchemaRequirement struct {
	// Table is the unqualified table name, as the module's SQL writes it.
	Table string
	// Column is the column name, as the module's SQL writes it.
	Column string
	// Version is the migration that adds the column.
	Version uint
}

// String renders "table.column (added by migration 000007)".
func (r SchemaRequirement) String() string {
	return fmt.Sprintf("%s.%s (added by migration %06d)", r.Table, r.Column, r.Version)
}

// schemaRequirements is every column identity/store names in SQL that migration
// 000001 does not create, sorted by version then table then column.
//
// Columns the BASE migration creates are deliberately absent. A consumer that
// has not run 000001 has no identity tables at all, is caught by the version-0
// branch of VerifySchemaVersion, and would learn nothing from a list of
// sixty-four columns; the interesting statement is which columns arrived LATER,
// because that is the set a partially-migrated consumer is missing.
//
// TestSchemaRequirementsMatchTheSQLTheModuleEmits re-derives this list from the
// module's own string literals cross-referenced against the DDL in
// identity/migrations, in BOTH directions, so it cannot silently become a list
// of things that used to be true. Read that test's doc comment before trusting
// the list: it states precisely what the derivation can and cannot see.
var schemaRequirements = []SchemaRequirement{
	{Table: "api_keys", Column: "expiry_notification_sent_at", Version: 3},
	{Table: "oidc_config", Column: "created_by", Version: 3},
	{Table: "oidc_config", Column: "extra_config", Version: 3},
	{Table: "oidc_config", Column: "name", Version: 3},
	{Table: "oidc_config", Column: "provider_type", Version: 3},
	{Table: "oidc_config", Column: "updated_by", Version: 3},
	{Table: "organizations", Column: "idp_name", Version: 3},
	{Table: "organizations", Column: "idp_type", Version: 3},
	{Table: "audit_logs", Column: "actor_email", Version: 7},
	{Table: "notify_dedup_claims", Column: "claimed_at", Version: 8},
	{Table: "notify_dedup_claims", Column: "dedup_key", Version: 8},
}

// SchemaRequirements returns every post-base column this module's SQL requires,
// sorted by the migration that adds it. The returned slice is a copy: a caller
// that mutates it cannot shrink what VerifySchemaVersion reports.
func SchemaRequirements() []SchemaRequirement {
	out := make([]SchemaRequirement, len(schemaRequirements))
	copy(out, schemaRequirements)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		if out[i].Table != out[j].Table {
			return out[i].Table < out[j].Table
		}
		return out[i].Column < out[j].Column
	})
	return out
}

// UnmetSchemaRequirements returns the requirements a database at the given
// identity migration version does not satisfy, sorted by version.
//
// It is exported so a consumer can render its own readiness payload without
// re-deriving the mapping from a version number to the columns that version is
// missing. An empty result means every column the module names exists.
func UnmetSchemaRequirements(version uint) []SchemaRequirement {
	var out []SchemaRequirement
	for _, r := range SchemaRequirements() {
		if version < r.Version {
			out = append(out, r)
		}
	}
	return out
}

// ErrSchemaVersion is the sentinel every schema-version failure wraps, so a
// consumer can tell "this database has not been migrated far enough" from a
// transport error and refuse to start rather than retrying. It is a
// configuration fault: retrying will not fix it.
var ErrSchemaVersion = errors.New("identity: schema version")

// VerifySchemaVersion asserts that db's identity migration chain is at
// RequiredSchemaVersion or later, and is not dirty.
//
// Call it ONCE at startup, before serving, on a handle that reaches the same
// database the repositories will use:
//
//	if err := identity.VerifySchemaVersion(ctx, identityDB); err != nil {
//	    return err // refuse to serve rather than fail every audited request
//	}
//
// It pairs with VerifySchemaRouting, which answers the neighbouring question —
// VerifySchemaVersion asks whether the identity chain has been applied far
// enough, VerifySchemaRouting asks whether the connection's search_path reaches
// the tables that chain created. Both are worth calling, and neither implies
// the other: a fully-migrated identity schema is no use to a connection pointed
// at the app's own public.users, and a correctly-routed connection still cannot
// write a column no migration has added.
//
// A consumer that calls RunMigrations(db, "up") at startup satisfies this by
// construction and may still call it: the chain is at head afterwards, so the
// check costs one round trip and returns nil. A consumer that migrates OUT OF
// BAND, or behind a feature flag, is the case this exists for.
//
// It fails closed. A chain that has never been applied, a chain below the
// required version, a chain marked dirty, and an unreadable version all return
// an error wrapping ErrSchemaVersion; only a readable, clean, sufficient
// version returns nil.
func VerifySchemaVersion(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("%w: no database handle supplied", ErrSchemaVersion)
	}

	version, dirty, err := migrationVersion(ctx, db)
	if err != nil {
		// Fail closed: an unreadable version is not a satisfied requirement.
		return fmt.Errorf("%w: could not read the identity migration version, so this "+
			"module cannot confirm the columns its SQL names exist: %w", ErrSchemaVersion, err)
	}

	return checkSchemaVersion(version, dirty)
}

// checkSchemaVersion is the decision, split from the round trip that feeds it
// so every branch is unit-testable without a database. VerifySchemaVersion is
// the only caller.
func checkSchemaVersion(version uint, dirty bool) error {
	if dirty {
		return fmt.Errorf("%w: the identity migration chain is at %06d and marked DIRTY — a "+
			"migration failed part-way, so the schema is in an unknown state and no column "+
			"this module names can be assumed to exist. Resolve the failed migration (inspect "+
			"identity.identity_schema_migrations, fix the cause, then force the version with "+
			"golang-migrate) before serving",
			ErrSchemaVersion, version)
	}

	unmet := UnmetSchemaRequirements(version)
	if version >= RequiredSchemaVersion && len(unmet) == 0 {
		return nil
	}

	var where string
	if version == 0 {
		where = "the identity migration chain has NEVER been applied to this database " +
			"(identity.identity_schema_migrations holds no version)"
	} else {
		where = fmt.Sprintf("the identity migration chain on this database is at %06d", version)
	}

	var missing []string
	for _, r := range unmet {
		missing = append(missing, r.String())
	}
	detail := "no column list is available"
	if len(missing) > 0 {
		detail = fmt.Sprintf("%d of %d column(s) this module's SQL names do not exist yet:\n  - %s",
			len(missing), len(schemaRequirements), strings.Join(missing, "\n  - "))
	}

	return fmt.Errorf("%w: this module's repositories require identity migration %06d or later, "+
		"and %s. %s\n"+
		"These columns are written and read UNCONDITIONALLY — there is no capability check and "+
		"no fallback — so the first request that touches one fails at runtime with SQLSTATE "+
		"42703 (undefined_column), long after startup reported success. Apply the identity "+
		"chain with identity.RunMigrations(db, \"up\") during startup, or run it out of band, "+
		"then restart. Note that the identity chain is SEPARATE from the consuming "+
		"application's own migrations: a log line saying the app's migrations completed says "+
		"nothing about this one",
		ErrSchemaVersion, RequiredSchemaVersion, where, detail)
}
