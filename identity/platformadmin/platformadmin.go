// Package platformadmin is the carrier mechanism for platform-admin authority:
// the grant table that says who administers ONE application, kept outside
// organization membership and outside the token.
//
// # Mechanism here, policy and DDL in the app
//
// This package owns no table. It is constructed against a table name the
// consuming application supplies, in whatever schema that application keeps its
// own authorization state — `registry.platform_admins`, `tsm.platform_admins`,
// or an unqualified name resolved through the connection's search_path. Two
// applications in one database therefore get two independent carriers, two
// independent administrator populations, and (see advisoryLockKey) two
// independent floor locks.
//
// The reason is the identity model this module exists to serve: identity is
// SHARED (who someone is, which organizations exist, who belongs to them) and
// authorization is PER-APPLICATION (what they may do HERE). "Who administers
// this application" is the second kind, so the row lives in the application's
// schema and only the mechanism is shared. See docs/platform-admin.md for the
// table shape the application must create, and why it carries no foreign keys.
//
// # The four properties this mechanism exists to keep
//
// PER REQUEST, NOT IN THE TOKEN. SessionScopes consults the carrier on every
// request rather than freezing an `admin` claim into a JWT. A session that
// outlives its authority is the whole hazard: without this, revoking the
// highest privilege in the product would take effect whenever the longest
// session happened to expire. One indexed read on a table with a handful of
// rows buys immediate revocation.
//
// API KEYS NEVER INHERIT IT. KeyScopes is a free function that takes no
// context, no connection and no user — it is structurally incapable of
// elevating anything, and it strips `admin` unconditionally. A long-lived CI
// credential silently carrying its owner's wildcard is the failure this shape
// makes unreachable rather than merely unlikely.
//
// THE FLOOR IS NEVER ZERO. Revoke reads the carrier under FOR UPDATE and hands
// the caller the grants that would REMAIN, in the same transaction as the
// delete. A deployment that revokes its last administrator has no recovery path
// short of hand-written SQL against the very table this API exists to replace.
//
// AN ORPHANED GRANT IS NOT AN ADMINISTRATOR. The carrier has no foreign key to
// identity, so a deleted user leaves its row behind; that row elevates nobody,
// because every elevation path loads the user first. RequireAnotherExercisableAdmin
// therefore counts only grants that still RESOLVE — and treats a failed lookup
// as an unresolved answer rather than as an orphan, so an identity outage
// cannot read as "everybody else is gone" and let the last real administrator
// revoke themselves.
//
// # Provenance
//
// A table rather than a boolean column, because it records who conferred the
// highest privilege in the product, when, and why: granted_by, granted_at,
// note. A re-grant leaves the original row ALONE (ErrAlreadyPlatformAdmin)
// rather than overwriting that provenance.
//
// Every mutation additionally requires an AuditIntentWriter and runs it INSIDE
// the mutation's own transaction. There is no "granted, but the audit write
// failed" branch: the record commits with the change or neither commits.
package platformadmin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
	"regexp"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/sethbacon/terraform-suite-identity/identity/store"
)

// Sentinels. Values rather than strings so a caller can tell WHICH refusal it
// received — a handler that maps "already an admin" and "the last one" onto the
// same status is serving two different facts as one.
var (
	// ErrNotConfigured reports that the carrier cannot be used as constructed:
	// no connection, an unusable table name, a nil receiver, or a mandatory
	// argument left out. It is a programming/wiring fault, never a decision
	// about a principal — and it is always FAIL-CLOSED: nothing is read,
	// nothing is written, and no authority is conferred.
	ErrNotConfigured = errors.New("platformadmin: carrier is not usable as configured")

	// ErrAlreadyPlatformAdmin is returned by Grant when the user already holds
	// a carrier row. The existing row is left ALONE rather than overwritten:
	// granted_by/granted_at/note are the provenance this table exists to keep,
	// and a re-grant that rewrote them would erase who originally conferred the
	// privilege.
	ErrAlreadyPlatformAdmin = errors.New("platformadmin: user already holds platform-admin")

	// ErrNotPlatformAdmin is returned by Revoke when there is no carrier row to
	// remove.
	//
	// It WRAPS store.ErrNotFound, which is this module's single not-found
	// sentinel (CONTRIBUTING.md): a by-identifier mutation that matched no row
	// is exactly that class, and a package with a second not-found sentinel has
	// none, because a caller cannot know which to test for. Both
	// errors.Is(err, ErrNotPlatformAdmin) and errors.Is(err, store.ErrNotFound)
	// answer true.
	ErrNotPlatformAdmin = fmt.Errorf("platformadmin: user does not hold platform-admin: %w", store.ErrNotFound)

	// ErrAuditIntentRequired is returned when a mutation is attempted with no
	// AuditIntentWriter.
	//
	// NOT AN OPTIONAL PARAMETER AND NOT A WARNING. A privileged mutation with
	// nowhere to record itself does not happen. The argument is mandatory so
	// that "forgot to audit it" fails closed at runtime rather than producing a
	// platform administrator nobody can account for.
	ErrAuditIntentRequired = errors.New("platformadmin: privileged mutation requires an audit intent writer")

	// ErrLastPlatformAdmin is the floor's refusal: the change would leave the
	// application with no exercisable platform administrator.
	ErrLastPlatformAdmin = errors.New("platformadmin: the last platform administrator cannot be revoked")

	// ErrIdentityUnavailable marks a failure to RESOLVE a principal, as
	// distinct from resolving it to "no such user".
	//
	// The two must not collapse. An identity store that is down would otherwise
	// read as "every remaining grant is an orphan", and the floor would let the
	// final administrator revoke themselves during exactly the incident in
	// which nobody can be added back.
	ErrIdentityUnavailable = errors.New("platformadmin: identity lookup failed")

	// ErrNotSerialized reports that the carrier-wide floor lock could not be
	// taken, so the change was NOT attempted. It is not a refusal for a policy
	// reason and it is not permission to proceed unserialised.
	ErrNotSerialized = errors.New("platformadmin: could not take the platform-admin floor lock")
)

// Grant is one row of the carrier.
type Grant struct {
	// UserID is the principal holding platform-admin authority. It references
	// an identity user by id and carries NO foreign key (docs/platform-admin.md).
	UserID string
	// GrantedBy is the acting principal, nil for a grant with no attributable
	// actor — a backfill, or a first-boot bootstrap.
	GrantedBy *string
	// GrantedAt is when the grant was recorded.
	GrantedAt time.Time
	// Note is a free-text operator note.
	Note *string
}

// AuditIntentWriter writes the audit record describing a mutation into that
// mutation's own transaction.
//
// A function rather than a repository handle, deliberately: this package must
// not know what an audit record looks like or where it eventually lands. It
// knows only that something has to be written before the commit and that a
// refusal here aborts the mutation. The application supplies the
// implementation — a transactional outbox, a direct insert into its own
// audit_logs, whatever it already has — and the content.
//
// It is handed the mutation's *sql.Tx. A writer that ignores that transaction
// and writes on another connection defeats the point: the record would then be
// able to fail, or to survive, independently of the change it describes.
type AuditIntentWriter func(ctx context.Context, tx *sql.Tx) error

// Predicate decides whether a revocation may proceed, given the grants that
// would REMAIN in the carrier afterwards.
//
// It is the caller's because "an administrator that remains" is not answerable
// from the carrier alone: a grant whose user no longer resolves is inert, and
// counting it would let the last real administrator revoke themselves against a
// count of two. RequireAnotherExercisableAdmin is the implementation this
// package ships; an application with a broader notion of authority can supply
// its own.
//
// It runs INSIDE the revoking transaction, after the carrier has been read
// under FOR UPDATE and before the DELETE. Returning a non-nil error aborts the
// revocation and the error reaches Revoke's caller unwrapped, so a sentinel
// survives errors.Is.
type Predicate func(ctx context.Context, remaining []Grant) error

// identifierPattern is a bare, unquoted SQL identifier: a letter or underscore
// followed by letters, digits, underscores or dollar signs. Postgres allows
// more inside double quotes, and that is precisely what is refused here — a
// table name is the one part of these queries that cannot be a bind parameter,
// so it is admitted only in the shape that has no interpretation beyond itself.
var identifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]*$`)

// maxIdentifierLen is Postgres's NAMEDATALEN-1. A longer name is silently
// TRUNCATED by the server, so two carriers configured with names differing
// only past this point would address one table while taking two different
// floor locks. Refused rather than truncated.
const maxIdentifierLen = 63

// Carrier reads and writes one application's platform-admin grant table.
type Carrier struct {
	db *sql.DB

	// table is the fully quoted, ready-to-interpolate table reference, e.g.
	// `"registry"."platform_admins"`. Built once by New from a validated name
	// so no query site does its own quoting.
	table string

	// lockKey namespaces this carrier's advisory lock, derived from table so
	// two applications sharing a database do not serialise against each other.
	lockKey int64

	// Prebuilt statements. Assembled in New rather than at each call site so
	// the table name is interpolated in exactly one place per statement and the
	// projection cannot drift between the three scan sites.
	existsQuery string
	listQuery   string
	lockQuery   string
	insertQuery string
	deleteQuery string

	// insideLock runs after the advisory lock is held and before Serialize
	// calls fn. Test-only: it is how the concurrency tests force an
	// interleaving that two goroutines started together are far too fast to
	// hit reliably. Always nil in production; there is no exported way to set
	// it.
	insideLock func(context.Context)
}

// grantColumns is the projection every read below uses, in one place so the
// three scan sites cannot drift apart.
const grantColumns = `user_id, granted_by, granted_at, note`

// New constructs a Carrier over db, addressing table.
//
// table is the application's OWN table, named either unqualified
// ("platform_admins", resolved through the connection's search_path) or
// schema-qualified ("registry.platform_admins"). Each part must be a bare SQL
// identifier; anything requiring quoting to be legal is refused with
// ErrNotConfigured rather than escaped, because a table name cannot be a bind
// parameter and the narrow shape is the only guarantee worth having.
//
// SPELL IT THE SAME WAY EVERYWHERE. The floor lock (Serialize) is namespaced by
// the name as given, so a deployment that constructs one process with
// "platform_admins" and another with "registry.platform_admins" addresses one
// table under two different locks and the serialisation between them is lost.
// Configure the name once and pass it through.
func New(db *sql.DB, table string) (*Carrier, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: no database connection", ErrNotConfigured)
	}
	quoted, err := quoteTable(table)
	if err != nil {
		return nil, err
	}
	return &Carrier{
		db:      db,
		table:   quoted,
		lockKey: advisoryLockKey(quoted),
		// #nosec G202 -- quoted is a validated, pq-quoted identifier built by
		// quoteTable; the table name is the one element of these statements
		// that cannot be a bind parameter. Every value is still a parameter.
		existsQuery: `SELECT EXISTS(SELECT 1 FROM ` + quoted + ` WHERE user_id = $1)`,
		// #nosec G202 -- see above.
		listQuery: `SELECT ` + grantColumns + ` FROM ` + quoted + ` ORDER BY granted_at ASC, user_id ASC`,
		// #nosec G202 -- see above.
		lockQuery: `SELECT ` + grantColumns + ` FROM ` + quoted + ` ORDER BY granted_at ASC, user_id ASC FOR UPDATE`,
		// #nosec G202 -- see above.
		insertQuery: `INSERT INTO ` + quoted + ` (user_id, granted_by, note) VALUES ($1, $2, $3) ` +
			`ON CONFLICT (user_id) DO NOTHING RETURNING ` + grantColumns,
		// #nosec G202 -- see above.
		deleteQuery: `DELETE FROM ` + quoted + ` WHERE user_id = $1`,
	}, nil
}

// quoteTable validates an unqualified or schema-qualified table name and
// returns it fully double-quoted.
func quoteTable(table string) (string, error) {
	trimmed := strings.TrimSpace(table)
	if trimmed == "" {
		return "", fmt.Errorf("%w: no table name", ErrNotConfigured)
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) > 2 {
		return "", fmt.Errorf("%w: table name %q has %d parts, want \"table\" or \"schema.table\"",
			ErrNotConfigured, table, len(parts))
	}
	quoted := make([]string, 0, len(parts))
	for _, p := range parts {
		if !identifierPattern.MatchString(p) {
			return "", fmt.Errorf("%w: %q in table name %q is not a bare SQL identifier",
				ErrNotConfigured, p, table)
		}
		if len(p) > maxIdentifierLen {
			return "", fmt.Errorf("%w: %q in table name %q is %d bytes, over Postgres's %d-byte limit",
				ErrNotConfigured, p, table, len(p), maxIdentifierLen)
		}
		quoted = append(quoted, pq.QuoteIdentifier(p))
	}
	return strings.Join(quoted, "."), nil
}

// advisoryLockKey namespaces the floor lock per carrier.
//
// Derived from the table reference rather than written as a magic number, so
// two applications sharing one database — the deployment this whole identity
// model is built for — do not block each other's administrator changes, and so
// nobody has to maintain a registry of hand-picked lock integers.
func advisoryLockKey(quotedTable string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("terraform-suite-identity/platformadmin\x00"))
	_, _ = h.Write([]byte(quotedTable))
	// The wrap to a negative int64 is intended, not an overflow bug:
	// pg_advisory_xact_lock takes a SIGNED bigint, every 64-bit pattern is a
	// distinct and equally valid lock key, and nothing here does arithmetic on
	// it. Masking the high bit instead would halve the key space for no gain.
	// #nosec G115 -- deliberate reinterpretation of a hash into Postgres's signed bigint lock key; no arithmetic follows.
	return int64(h.Sum64())
}

// IsPlatformAdmin reports whether the user holds platform-admin authority
// through the carrier.
//
// An empty userID answers false WITHOUT querying. Not a micro-optimisation:
// user_id is UUID, so an empty string reaches Postgres as an invalid-input
// error, and an authorization path must not have to tell a malformed principal
// apart from a database fault. "No principal" is a clean no, and the fail-closed
// direction.
//
// Any other error is returned rather than swallowed. This is a GRANT-direction
// lookup, so a failure can only ever withhold authority, never widen it; the
// caller decides whether an unresolved answer aborts the request or merely
// leaves the principal unelevated.
func (c *Carrier) IsPlatformAdmin(ctx context.Context, userID string) (bool, error) {
	if c == nil || c.db == nil {
		return false, fmt.Errorf("%w: IsPlatformAdmin on an unconstructed carrier", ErrNotConfigured)
	}
	if userID == "" {
		return false, nil
	}
	var isAdmin bool
	if err := c.db.QueryRowContext(ctx, c.existsQuery, userID).Scan(&isAdmin); err != nil {
		return false, err
	}
	return isAdmin, nil
}

func scanGrant(s interface{ Scan(...any) error }) (*Grant, error) {
	g := &Grant{}
	if err := s.Scan(&g.UserID, &g.GrantedBy, &g.GrantedAt, &g.Note); err != nil {
		return nil, err
	}
	return g, nil
}

// List returns every carrier row, oldest grant first.
//
// UNFILTERED, AND THAT IS THE POINT. A grant whose user no longer resolves is
// still returned: the caller labels it rather than dropping it. Filtering here
// would make a live row invisible to the only surface that can remove it.
func (c *Carrier) List(ctx context.Context) ([]Grant, error) {
	if c == nil || c.db == nil {
		return nil, fmt.Errorf("%w: List on an unconstructed carrier", ErrNotConfigured)
	}
	rows, err := c.db.QueryContext(ctx, c.listQuery)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	grants := make([]Grant, 0)
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		grants = append(grants, *g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return grants, nil
}

// Grant records platform-admin authority for userID.
//
// Returns ErrAlreadyPlatformAdmin when the user already holds a carrier row —
// ON CONFLICT DO NOTHING, so the original provenance survives a re-grant. The
// caller turns that into a conflict rather than a silent success, because
// "already an admin" and "granted just now, by you" are different facts about
// who is accountable for the privilege.
//
// grantedBy is the acting principal, nil for a grant with no attributable actor
// (a backfill, or a first-boot bootstrap).
//
// IN A TRANSACTION, FOR THE AUDIT RECORD. The insert is a single statement and
// needs no transaction of its own; it has one so writeAuditIntent can enlist in
// it. The grant and the record of the grant then commit together or not at all
// — which is the whole point, because the previous shape everywhere (mutate,
// then write the entry, then log the failure and report success) can produce a
// platform administrator nobody can account for.
//
// writeAuditIntent is MANDATORY: nil is refused with ErrAuditIntentRequired
// before anything is written.
//
// The TARGET IS NOT RESOLVED HERE. Granting to an id that answers to nobody
// mints an orphan on purpose, and refusing that is the application's guard
// because only the application knows where its principals resolve; see
// docs/platform-admin.md.
func (c *Carrier) Grant(ctx context.Context, userID string, grantedBy, note *string, writeAuditIntent AuditIntentWriter) (*Grant, error) {
	if c == nil || c.db == nil {
		return nil, fmt.Errorf("%w: Grant on an unconstructed carrier", ErrNotConfigured)
	}
	if writeAuditIntent == nil {
		return nil, ErrAuditIntentRequired
	}
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("%w: Grant names no principal", ErrNotConfigured)
	}

	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	// Rolled back unconditionally; a Rollback after a successful Commit is a
	// no-op returning sql.ErrTxDone, which is why only the Commit error is
	// reported.
	defer func() { _ = tx.Rollback() }()

	g, err := scanGrant(tx.QueryRowContext(ctx, c.insertQuery, userID, grantedBy, note))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAlreadyPlatformAdmin
	}
	if err != nil {
		return nil, err
	}

	// After the mutation, so the intent can describe what actually landed — and
	// before the commit, so a refusal here takes the grant with it.
	if err := writeAuditIntent(ctx, tx); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return g, nil
}

// lockCarrier reads every grant inside tx under FOR UPDATE, separating the one
// addressed by userID (nil when there is none) from the ones that would remain
// after it is removed.
func (c *Carrier) lockCarrier(ctx context.Context, tx *sql.Tx, userID string) (*Grant, []Grant, error) {
	rows, err := tx.QueryContext(ctx, c.lockQuery)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = rows.Close() }()

	var target *Grant
	var remaining []Grant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, nil, err
		}
		if g.UserID == userID {
			target = g
			continue
		}
		remaining = append(remaining, *g)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return target, remaining, nil
}

// Revoke removes userID's carrier row, but only if keepsAnAdmin accepts the
// grants that would REMAIN afterwards.
//
// UNDER A LOCK, NOT CHECK-THEN-DELETE. The read takes FOR UPDATE and the delete
// runs in the same transaction, so two administrators revoking each other
// concurrently serialise: the second one's read blocks, then sees a set with the
// first's row already gone. Without the lock both would see the other still
// present, both would pass the predicate, and the deployment would end with zero
// administrators — the exact outcome the guard exists to prevent, reachable by
// two well-formed requests.
//
// keepsAnAdmin is MANDATORY. Registry's original made it optional and skipped
// the check when nil; that is the one way the floor can be silently absent, and
// an application that genuinely wants no floor can say so in one explicit line.
//
// writeAuditIntent records the revocation in the SAME transaction as the delete
// and is likewise MANDATORY — nil is refused before the lock is taken. A
// revocation that could not be recorded is not performed.
//
// Returns ErrNotPlatformAdmin when there is no row to remove, the predicate's
// own error when it refuses, and the driver's error otherwise. Nothing is
// deleted in any of those cases.
//
// THE ROW LOCK REACHES ONLY THIS TABLE. It serialises revoke against revoke. If
// the application has OTHER writes that reduce administrator authority — a
// membership demotion, a user deletion — wrap this call and those writes in
// Serialize so they order against each other too.
func (c *Carrier) Revoke(ctx context.Context, userID string, keepsAnAdmin Predicate, writeAuditIntent AuditIntentWriter) (*Grant, error) {
	if c == nil || c.db == nil {
		return nil, fmt.Errorf("%w: Revoke on an unconstructed carrier", ErrNotConfigured)
	}
	if writeAuditIntent == nil {
		return nil, ErrAuditIntentRequired
	}
	if keepsAnAdmin == nil {
		return nil, fmt.Errorf("%w: Revoke requires a floor predicate", ErrNotConfigured)
	}
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("%w: Revoke names no principal", ErrNotConfigured)
	}

	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	target, remaining, err := c.lockCarrier(ctx, tx, userID)
	if err != nil {
		return nil, err
	}
	if target == nil {
		return nil, ErrNotPlatformAdmin
	}
	if err := keepsAnAdmin(ctx, remaining); err != nil {
		return nil, err
	}

	res, err := tx.ExecContext(ctx, c.deleteQuery, userID)
	if err != nil {
		return nil, err
	}
	// The row was present under FOR UPDATE moments ago, so zero rows here means
	// the lock did not hold what it is supposed to hold. Refusing to commit is
	// the only safe reading: reporting a revocation that did not happen would
	// leave an administrator the operator believes is gone.
	affected, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if affected != 1 {
		return nil, fmt.Errorf("platformadmin: revoking %s removed %d rows, want 1", userID, affected)
	}
	// Inside the same transaction as the DELETE: a refusal here rolls the
	// revocation back rather than leaving an unrecorded loss of privilege.
	if err := writeAuditIntent(ctx, tx); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return target, nil
}

// Serialize runs fn under this carrier's application-wide advisory lock.
//
// FOR THE WRITES REVOKE'S ROW LOCK CANNOT REACH. Revoke serialises against
// another Revoke by holding FOR UPDATE over the carrier. It does not serialise
// against a membership demotion, a user deletion or a GDPR erasure — writes on
// other tables, possibly on another connection or another database entirely,
// that nonetheless reduce who can administer the application. Two such changes
// can each observe the other's administrator still standing and both commit.
// Running every authority-reducing write inside Serialize orders them.
//
// The lock is pg_advisory_xact_lock, scoped to a transaction that carries no
// writes and exists only to hold it: it is released by the rollback below
// however this function exits. The session-level pg_advisory_lock would need a
// hand-written unlock on every path and would leak the lock forever if one were
// missed.
//
// A failure to take the lock returns ErrNotSerialized and fn is NOT run — an
// unserialised change is not a safe fallback for a serialised one. fn's own
// error is returned unwrapped so sentinels survive errors.Is.
//
// fn runs INSIDE the lock: it must not be long-running, and it must not call
// Serialize again on the same carrier.
func (c *Carrier) Serialize(ctx context.Context, fn func(context.Context) error) error {
	if fn == nil {
		return fmt.Errorf("%w: Serialize was given nothing to run", ErrNotConfigured)
	}
	if c == nil || c.db == nil {
		return fmt.Errorf("%w: Serialize on an unconstructed carrier", ErrNotConfigured)
	}

	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotSerialized, err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, c.lockKey); err != nil {
		return fmt.Errorf("%w: %v", ErrNotSerialized, err)
	}

	if c.insideLock != nil {
		c.insideLock(ctx)
	}
	return fn(ctx)
}
