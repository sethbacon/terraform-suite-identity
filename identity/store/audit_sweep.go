// audit_sweep.go makes AuditRepository's retention sweep OPTIONALLY exempt rows
// a consuming app has placed under legal hold.
//
// # The mechanism is here; the policy is not
//
// This module owns audit_logs — it ships the migration, the writes and the
// reads. What it does not own, and cannot, is the question of which rows an
// investigation needs preserved: that is a compliance decision belonging to the
// deployment, along with who may place a hold, what it is called, and how long
// retention runs at all (RetentionDays has always been the host's, which is why
// the delete carried no policy hook until now).
//
// So the library owns the SENTENCE — "a row inside an active hold's date range
// is not deleted" — and renders the table that sentence reads. The app owns the
// table itself, in its own numbered migration, and every API around it.
//
// # Why an option rather than a predicate baked into the statement
//
// A NOT EXISTS against a table that does not exist is NOT an empty set. Postgres
// resolves relation names at parse time, so the statement raises SQLSTATE 42P01
// (undefined_table) before it examines a single row — verified against
// PostgreSQL 16, where the DELETE errored with `relation "no_such_holds" does
// not exist` and the row it would have removed survived.
//
// terraform-state-manager consumes this same AuditRepository and has no
// legal_holds table. It has no retention job today, so a hard-coded predicate
// would break nothing this afternoon; it would break every sweep on the day that
// job is added (sethbacon/terraform-state-manager-backend#373), which is
// precisely the kind of latent, someone-else's-repo failure that is worst to
// diagnose.
//
// This is the same shape channel_scope.go uses for notification_channels'
// organization_id, and for the same reason: one consumer's schema carries
// something the other's does not, the difference is knowable at wire-up time,
// and the zero value must emit the statement this package has always emitted.
//
//	repo.DeleteAuditLogsBefore(ctx, cutoff, batch)                              // no holds here
//	repo.DeleteAuditLogsBefore(ctx, cutoff, batch, store.WithLegalHolds("legal_holds"))
//
// An absent option is not a hold check that failed open. It is a statement that
// this deployment has no holds table — and a deployment that gets that wrong is
// caught at startup by VerifyLegalHoldTable rather than by a sweep that quietly
// deleted the evidence.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	"github.com/sethbacon/terraform-suite-identity/identity/internal/pgquote"
)

// LegalHoldColumns are the columns a held-row check reads. They are exported so
// a consumer's migration and its documentation can name the columns this package
// will actually address rather than a copy of the strings.
const (
	LegalHoldActiveColumn    = "active"
	LegalHoldStartDateColumn = "start_date"
	LegalHoldEndDateColumn   = "end_date"
)

// AuditSweepOption modifies how the retention sweep selects rows for deletion.
// The only option today is WithLegalHolds.
type AuditSweepOption func(*auditSweepFilter)

// auditSweepFilter is the accumulated effect of a sweep's options. Its ZERO
// VALUE is the unexempted sweep — the statement this package has always emitted
// — so a caller that passes no options deletes exactly what it did before, and
// does not get a hold check that silently matched nothing.
type auditSweepFilter struct {
	holdTable string
}

// WithLegalHolds exempts from deletion any audit row whose created_at falls
// inside an ACTIVE hold's [start_date, end_date] range, as recorded in table.
//
// Pass it only against a table shaped like LegalHoldTableDDL;
// VerifyLegalHoldTable asserts that at startup, and calling it once is how a
// consumer turns "we intend to honour holds" into a checked fact rather than an
// assumption every sweep re-makes.
//
// table may be "legal_holds" or "schema.legal_holds". It is an identifier, not a
// value, so it cannot be a bind parameter; it is quoted and validated at
// statement build time and a malformed one is an error rather than a string
// pasted into SQL.
//
// A hold is honoured while `active` is true, regardless of released_at: release
// is the app's word for what it did, and this package reads the one column that
// says whether the hold is in force. A row inside a released hold becomes
// deletable on the next sweep, which is the intended behaviour — the evidence
// was preserved for as long as the hold stood.
func WithLegalHolds(table string) AuditSweepOption {
	return func(f *auditSweepFilter) {
		f.holdTable = table
	}
}

func newAuditSweepFilter(opts []AuditSweepOption) auditSweepFilter {
	var f auditSweepFilter
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&f)
	}
	return f
}

// exemption renders the NOT EXISTS clause for the sweep's inner SELECT, or an
// empty string when no holds table was named.
//
// THE CLAUSE BELONGS INSIDE THE `LIMIT` SUBSELECT, never in the outer WHERE.
// The sweep pages through history oldest-first; a filter applied after LIMIT
// would let a batch fill entirely with held rows, delete none of them, and hand
// the caller's loop the same batch forever — a sweep that reports zero progress
// and never reaches the deletable rows behind them. Inside the subselect the
// held rows are never selected in the first place, so each batch is a full
// batch of deletable rows and the loop terminates.
func (f auditSweepFilter) exemption() (string, error) {
	if f.holdTable == "" {
		return "", nil
	}
	quoted, err := quoteAuditTable(f.holdTable)
	if err != nil {
		return "", err
	}
	// Not a #nosec: gosec does not flag this Sprintf, because the string is
	// returned rather than handed to a database call here. Recorded anyway —
	// quoted is validated against auditIdentifierPattern and escaped by
	// pgquote.Identifier, and the column names are compile-time constants, so
	// nothing caller-controlled reaches the SQL.
	return fmt.Sprintf(`
			  AND NOT EXISTS (
			      SELECT 1 FROM %s h
			      WHERE h.%s
			        AND audit_logs.created_at >= h.%s
			        AND audit_logs.created_at <= h.%s
			  )`,
		quoted, LegalHoldActiveColumn, LegalHoldStartDateColumn, LegalHoldEndDateColumn), nil
}

// LegalHoldTableDDL renders the CREATE TABLE a consumer should place in its own
// numbered migration.
//
// Rendered here rather than migrated here because this module does not own the
// table: the app decides whether it has holds at all, and a module-owned
// migration would create an unused table in every consumer. The same split
// platformadmin.TableDDL and auditoutbox.OutboxDDL already use.
//
// Shipping the shape from the package that READS it is what keeps the two from
// drifting: a consumer that hand-wrote a compatible-looking table would find out
// it was wrong when a sweep failed, which is the wrong moment.
//
// The index is the one the exemption needs: the sweep asks "is there an active
// hold covering this instant?" once per candidate row.
func LegalHoldTableDDL(table string) (string, error) {
	quoted, err := quoteAuditTable(table)
	if err != nil {
		return "", err
	}
	indexName, err := legalHoldIndexName(table)
	if err != nil {
		return "", err
	}
	// Both identifiers are validated and escaped above. Not a #nosec for the
	// same reason as exemption's: this renders DDL for a caller's migration and
	// executes nothing.
	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    id           UUID PRIMARY KEY,
    name         TEXT NOT NULL,
    reason       TEXT NOT NULL DEFAULT '',
    start_date   TIMESTAMPTZ NOT NULL,
    end_date     TIMESTAMPTZ NOT NULL,
    active       BOOLEAN NOT NULL DEFAULT TRUE,
    placed_by    UUID,
    placed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_by  UUID,
    released_at  TIMESTAMPTZ,
    CONSTRAINT %s_range CHECK (end_date >= start_date)
);
CREATE INDEX IF NOT EXISTS %s ON %s (start_date, end_date) WHERE active;`,
		quoted, strings.ReplaceAll(bareName(table), ".", "_"), indexName, quoted), nil
}

// VerifyLegalHoldTable reports whether table is present and shaped the way the
// exemption reads it. Call it at startup, on the SAME connection the sweep will
// run on.
//
// That last part is the trap this function exists to catch. audit_logs may live
// on a separate identity database while the app's own pool serves everything
// else, and a holds table created on the app pool would be invisible to a sweep
// running on the identity one — every hold placed, every UI confirming it, and
// every sweep deleting the rows anyway. A missing table is reported here rather
// than discovered by the deletion.
func VerifyLegalHoldTable(ctx context.Context, db *sql.DB, table string) error {
	if db == nil {
		return fmt.Errorf("legal-hold table %q: no database connection", table)
	}
	quoted, err := quoteAuditTable(table)
	if err != nil {
		return err
	}
	// A zero-row probe: it fails if the relation is absent (42P01) or if any
	// column the exemption reads is missing (42703), and touches no data.
	//
	// QueryContext, not ExecContext. It is a SELECT, and the repo's
	// TestNotFoundClass_ExecResultDiscardersAreEnumerated is right to refuse an
	// Exec whose result nobody reads — for a statement meant to change rows
	// that is how a no-op passes for work. Here there is no result to read at
	// all; the answer is entirely in whether the statement planned.
	// #nosec G201 -- this Sprintf DOES reach a database call, which is why it
	// is the one suppression in this file that gosec exercises. quoted is
	// validated against auditIdentifierPattern and escaped by
	// pgquote.Identifier; the three column names are compile-time constants.
	probe := fmt.Sprintf(`SELECT %s, %s, %s FROM %s WHERE false`,
		LegalHoldActiveColumn, LegalHoldStartDateColumn, LegalHoldEndDateColumn, quoted)
	rows, err := db.QueryContext(ctx, probe)
	if err != nil {
		return fmt.Errorf("legal-hold table %q is not readable as the audit sweep will read it "+
			"(create it from store.LegalHoldTableDDL, on the same database as audit_logs): %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("legal-hold table %q: %w", table, err)
	}
	return nil
}

func bareName(table string) string {
	parts := strings.Split(strings.TrimSpace(table), ".")
	return parts[len(parts)-1]
}

func legalHoldIndexName(table string) (string, error) {
	name := "idx_" + bareName(table) + "_active_range"
	if !auditIdentifierPattern.MatchString(name) {
		return "", fmt.Errorf("legal-hold table %q yields an invalid index name %q", table, name)
	}
	if len(name) > maxAuditIdentifierLen {
		name = name[:maxAuditIdentifierLen]
	}
	return pgquote.Identifier(name), nil
}

var auditIdentifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]*$`)

const maxAuditIdentifierLen = 63

// quoteAuditTable validates and quotes a "table" or "schema.table" reference.
// Mirrors platformadmin.quoteTable; kept here because the two packages do not
// import each other and a shared internal helper for two call sites would be a
// package whose only purpose is to be shared.
func quoteAuditTable(table string) (string, error) {
	trimmed := strings.TrimSpace(table)
	if trimmed == "" {
		return "", fmt.Errorf("legal-hold table: no table name")
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) > 2 {
		return "", fmt.Errorf("legal-hold table %q has %d parts, want \"table\" or \"schema.table\"",
			table, len(parts))
	}
	quoted := make([]string, 0, len(parts))
	for _, p := range parts {
		if !auditIdentifierPattern.MatchString(p) {
			return "", fmt.Errorf("%q in legal-hold table %q is not a bare SQL identifier", p, table)
		}
		if len(p) > maxAuditIdentifierLen {
			return "", fmt.Errorf("%q in legal-hold table %q is %d bytes, over Postgres's %d-byte limit",
				p, table, len(p), maxAuditIdentifierLen)
		}
		quoted = append(quoted, pgquote.Identifier(p))
	}
	return strings.Join(quoted, "."), nil
}
