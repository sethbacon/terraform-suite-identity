// ddl.go renders the schema this package's code addresses, for the CONSUMING
// APP's own migration set.
//
// # Why this package ships no migration
//
// Phase 1 of issue #206 changes no `identity.*` schema at all, and it could not
// own these tables even if it wanted to. The outbox sits beside the mutation it
// audits, on the app's connection, in the app's schema; the destination
// `audit_logs` becomes per-app under the same model. A migration here would
// create a second, empty pair somewhere the app is not looking — the failure
// identity/notify's schema.go describes at length, one table over.
//
// So the app owns the physical objects and this package owns their SHAPE. What
// it renders is not a template to adapt: it is the definition its own
// statements, and its own constraint trigger, were written against.
//
// # The trigger is the point
//
// OutboxDDL alone gives an app a queue. TriggerSpec.DDL gives it the property:
// a DEFERRABLE INITIALLY DEFERRED constraint trigger on the mutated table that
// re-checks, AT COMMIT, that this transaction wrote an intent naming this
// subject with this action. A mutation without one does not commit. That is the
// difference between a property the code intends and a property the database
// enforces — it holds for a future handler that forgets, for a migration, and
// for the hand-written SQL that a management API was built to replace.
//
// # Why pg_current_xact_id() and not a foreign key
//
// "Same transaction" is the property being enforced, and no constraint can
// express it: a foreign key would be satisfied by an intent written days
// earlier. pg_current_xact_id() is the top-level transaction id, recorded on the
// intent as it is written and compared at commit. It requires PostgreSQL 13+.
package auditoutbox

import (
	"fmt"
	"strings"

	"github.com/sethbacon/terraform-suite-identity/identity/internal/pgquote"
)

// assertIntentSuffix and requireIntentSuffix name the generated functions.
const (
	assertIntentSuffix  = "_assert_intent"
	requireIntentSuffix = "_require_audit_intent"
)

// OutboxDDL renders the outbox table, its indexes and the same-transaction
// assertion function, for outboxTable.
//
// Apply it from the app's own migration set. The statement is idempotent
// (CREATE TABLE IF NOT EXISTS / CREATE OR REPLACE FUNCTION), so re-running a
// migration does not fight it.
//
// The DESTINATION table is the app's existing audit_logs and is deliberately not
// rendered here: this package does not own it, does not know what else the app
// stores in it, and adapts to the columns it finds (sink.go). It requires only
// that `id` is the primary key or carries a UNIQUE index — that is what
// ON CONFLICT (id) DO NOTHING needs, and it is what makes an at-least-once
// redelivery a no-op instead of a duplicate audit entry.
func OutboxDDL(outboxTable string) (string, error) {
	t, err := parseTable("outbox table", outboxTable)
	if err != nil {
		return "", err
	}
	assert, err := t.derive(assertIntentSuffix)
	if err != nil {
		return "", err
	}
	// Index names are not schema-qualified in CREATE INDEX; they take the
	// table's schema. Derive and length-check them all the same.
	pendingIdx, err := t.derive("_pending_idx")
	if err != nil {
		return "", err
	}
	deliveredIdx, err := t.derive("_delivered_idx")
	if err != nil {
		return "", err
	}
	txidIdx, err := t.derive("_txid_idx")
	if err != nil {
		return "", err
	}

	name := t.sql()
	return `-- Rendered by identity/auditoutbox.OutboxDDL(` + pgquote.Literal(t.String()) + `).
-- The transactional audit outbox: an audit INTENT written in the same
-- transaction as the privileged mutation it describes, delivered afterwards.
CREATE TABLE IF NOT EXISTS ` + name + ` (
    -- Chosen by the writer BEFORE the mutation commits, and reused verbatim as
    -- the destination row's id. That is what makes redelivery idempotent: the
    -- second attempt conflicts on the destination's primary key.
    event_id        UUID         PRIMARY KEY,
    -- The transaction that wrote this intent. Read only by the trigger.
    txid            xid8         NOT NULL DEFAULT pg_current_xact_id(),
    -- When the audited event happened, not when it was delivered. Delivery may
    -- be minutes later; the audit trail must say the former.
    occurred_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    action          VARCHAR(500) NOT NULL,
    actor_user_id   UUID,
    -- The actor's address as it stood at the time, denormalised so the entry
    -- stays attributable after the user row is gone. This package never
    -- resolves it from a users table: identity may be another database.
    actor_email     VARCHAR(255),
    organization_id UUID,
    resource_type   VARCHAR(100),
    resource_id     VARCHAR(255),
    ip_address      VARCHAR(45),
    metadata        JSONB,
    -- Delivery bookkeeping. delivered_at IS NULL is the backlog.
    delivered_at    TIMESTAMPTZ,
    attempts        INTEGER      NOT NULL DEFAULT 0,
    last_error      TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- The relay's claim scan. Partial, on the undelivered rows only, so it stays
-- small no matter how much delivered history has yet to be pruned.
CREATE INDEX IF NOT EXISTS ` + pgquote.Identifier(pendingIdx.name) + `
    ON ` + name + ` (occurred_at, event_id) WHERE delivered_at IS NULL;

-- The pruner's scan over delivered history.
CREATE INDEX IF NOT EXISTS ` + pgquote.Identifier(deliveredIdx.name) + `
    ON ` + name + ` (delivered_at) WHERE delivered_at IS NOT NULL;

-- The trigger's same-transaction lookup. Every commit that touches a guarded
-- table runs it, so it is not optional.
CREATE INDEX IF NOT EXISTS ` + pgquote.Identifier(txidIdx.name) + `
    ON ` + name + ` (txid, resource_type, resource_id);

-- Raises unless the CURRENT transaction has already written an intent naming
-- this subject with this action.
--
-- resource_id is compared case-insensitively: uuid::text is canonical lower
-- case, but an operator writing an intent by hand may not be.
CREATE OR REPLACE FUNCTION ` + assert.sql() + `(
    subject TEXT, resource TEXT, expected_action TEXT
) RETURNS void AS $$
BEGIN
    IF subject IS NULL THEN
        RAISE EXCEPTION 'audit outbox: refusing a % mutation with no subject to audit', resource
            USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM ` + name + ` o
         WHERE o.txid = pg_current_xact_id()
           AND o.resource_type = resource
           AND lower(o.resource_id) = lower(subject)
           AND o.action = expected_action
    ) THEN
        RAISE EXCEPTION 'audit outbox: % on % has no audit intent in this transaction (expected a ` + t.String() + ` row with action=%, resource_type=%, resource_id=%)',
            expected_action, subject, expected_action, resource, subject
            USING ERRCODE = '23514',
                  HINT = 'Write the audit intent in the same transaction as the mutation: identity/auditoutbox, Outbox.Enqueue.';
    END IF;
END;
$$ LANGUAGE plpgsql;
`, nil
}

// OutboxDropDDL renders the down migration for OutboxDDL.
//
// ROLLING IT BACK REOPENS THE HOLE, and the app's own down migration must drop
// every TriggerSpec first: a trigger left behind on a dropped outbox fails every
// mutation at commit with a missing relation instead of a clean refusal.
// Undelivered intents are destroyed with the table, so drain the backlog first
// if any of it still matters. Delivered intents are safe to lose — the
// destination rows are the record.
func OutboxDropDDL(outboxTable string) (string, error) {
	t, err := parseTable("outbox table", outboxTable)
	if err != nil {
		return "", err
	}
	assert, err := t.derive(assertIntentSuffix)
	if err != nil {
		return "", err
	}
	return `DROP FUNCTION IF EXISTS ` + assert.sql() + `(TEXT, TEXT, TEXT);
DROP TABLE IF EXISTS ` + t.sql() + `;
`, nil
}

// TriggerSpec describes the constraint trigger binding one table's mutations to
// an audit intent.
//
// The ACTIONS ARE PINNED IN THE DATABASE on purpose. An intent that merely
// mentions the subject would let a revocation be committed under a grant's
// record, so the trigger matches the action verbatim. Renaming an action in Go
// without re-rendering this makes the mutation fail loudly at commit rather than
// pass unaudited — which is the correct direction to fail.
type TriggerSpec struct {
	// Outbox is the outbox table the intent must appear in.
	Outbox string
	// Table is the mutated table to guard.
	Table string
	// SubjectColumn is the column naming the audited subject — the value the
	// intent must carry as ResourceID (e.g. "user_id" on a platform_admins
	// carrier). Compared as text, case-insensitively.
	SubjectColumn string
	// ResourceType is the Intent.ResourceType the trigger matches.
	ResourceType string
	// OnInsert, OnUpdate and OnDelete are the Intent.Action each operation
	// requires. An empty string leaves that operation UNGUARDED — say so
	// deliberately, because an unguarded operation is a way to change the row
	// without a record.
	OnInsert string
	OnUpdate string
	OnDelete string
}

// DDL renders the trigger function and the constraint trigger for this spec.
func (s TriggerSpec) DDL() (string, error) {
	outbox, guarded, fn, err := s.names()
	if err != nil {
		return "", err
	}
	assert, err := outbox.derive(assertIntentSuffix)
	if err != nil {
		return "", err
	}

	var events []string
	var branches []string
	subject := pgquote.Identifier(s.SubjectColumn)
	resource := pgquote.Literal(s.ResourceType)

	if s.OnInsert != "" {
		events = append(events, "INSERT")
		branches = append(branches, `    IF TG_OP = 'INSERT' THEN
        PERFORM `+assert.sql()+`(NEW.`+subject+`::text, `+resource+`, `+pgquote.Literal(s.OnInsert)+`);
    END IF;
`)
	}
	if s.OnUpdate != "" {
		events = append(events, "UPDATE")
		// A repointed subject is TWO subjects and needs an intent for each,
		// otherwise the row could be moved to a different principal under one
		// record.
		branches = append(branches, `    IF TG_OP = 'UPDATE' THEN
        PERFORM `+assert.sql()+`(OLD.`+subject+`::text, `+resource+`, `+pgquote.Literal(s.OnUpdate)+`);
        IF NEW.`+subject+` IS DISTINCT FROM OLD.`+subject+` THEN
            PERFORM `+assert.sql()+`(NEW.`+subject+`::text, `+resource+`, `+pgquote.Literal(s.OnUpdate)+`);
        END IF;
    END IF;
`)
	}
	if s.OnDelete != "" {
		events = append(events, "DELETE")
		branches = append(branches, `    IF TG_OP = 'DELETE' THEN
        PERFORM `+assert.sql()+`(OLD.`+subject+`::text, `+resource+`, `+pgquote.Literal(s.OnDelete)+`);
    END IF;
`)
	}

	body := strings.Join(branches, "")

	return `-- Rendered by identity/auditoutbox.TriggerSpec.DDL for ` + guarded.String() + `.
CREATE OR REPLACE FUNCTION ` + fn.sql() + `() RETURNS TRIGGER AS $$
BEGIN
` + body + `    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- DEFERRABLE INITIALLY DEFERRED: the check runs at COMMIT, so the mutation and
-- its intent may be written in either order within the transaction, and the
-- failure aborts the commit rather than one statement.
DROP TRIGGER IF EXISTS ` + pgquote.Identifier(fn.name) + ` ON ` + guarded.sql() + `;
CREATE CONSTRAINT TRIGGER ` + pgquote.Identifier(fn.name) + `
    AFTER ` + strings.Join(events, " OR ") + ` ON ` + guarded.sql() + `
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION ` + fn.sql() + `();
`, nil
}

// DropDDL renders the down migration for DDL. Drop the trigger BEFORE the
// outbox table it reads, or every mutation fails at commit with a missing
// relation instead of a clean refusal.
func (s TriggerSpec) DropDDL() (string, error) {
	_, guarded, fn, err := s.names()
	if err != nil {
		return "", err
	}
	return `DROP TRIGGER IF EXISTS ` + pgquote.Identifier(fn.name) + ` ON ` + guarded.sql() + `;
DROP FUNCTION IF EXISTS ` + fn.sql() + `();
`, nil
}

// names validates the spec and returns the outbox, the guarded table and the
// generated trigger-function name.
func (s TriggerSpec) names() (outbox, guarded, fn table, err error) {
	outbox, err = parseTable("outbox table", s.Outbox)
	if err != nil {
		return table{}, table{}, table{}, err
	}
	guarded, err = parseTable("guarded table", s.Table)
	if err != nil {
		return table{}, table{}, table{}, err
	}
	if s.SubjectColumn == "" {
		return table{}, table{}, table{}, fmt.Errorf("%w: TriggerSpec for %s names no SubjectColumn; "+
			"the trigger has nothing to match the intent's ResourceID against", ErrInvalidTable, s.Table)
	}
	if err := validateIdentifier("subject column", s.SubjectColumn, s.SubjectColumn); err != nil {
		return table{}, table{}, table{}, err
	}
	if strings.TrimSpace(s.ResourceType) == "" {
		return table{}, table{}, table{}, fmt.Errorf("%w: TriggerSpec for %s names no ResourceType; "+
			"the trigger matches the intent on it, so an empty one matches nothing and every "+
			"mutation would be refused", ErrInvalidTable, s.Table)
	}
	if s.OnInsert == "" && s.OnUpdate == "" && s.OnDelete == "" {
		// Failing on an empty universe. A trigger that guards no operation
		// compiles, installs, fires on nothing, and reads as protection.
		return table{}, table{}, table{}, fmt.Errorf("%w: TriggerSpec for %s guards no operation "+
			"(OnInsert, OnUpdate and OnDelete are all empty); it would install and enforce nothing",
			ErrInvalidTable, s.Table)
	}
	fn, err = guarded.derive(requireIntentSuffix)
	if err != nil {
		return table{}, table{}, table{}, err
	}
	return outbox, guarded, fn, nil
}
