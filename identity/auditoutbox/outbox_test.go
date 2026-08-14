package auditoutbox

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

const testOutboxTable = "registry.audit_outbox"

func newOutbox(t *testing.T) (*Outbox, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet sqlmock expectations: %v", err)
		}
	})
	o, err := New(db, testOutboxTable)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return o, mock
}

func TestNew(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if _, err := New(nil, testOutboxTable); !errors.Is(err, ErrNoOutbox) {
		t.Errorf("New(nil db) = %v, want ErrNoOutbox", err)
	}
	if _, err := New(db, "Audit_Outbox"); !errors.Is(err, ErrInvalidTable) {
		t.Errorf("New(bad table) = %v, want ErrInvalidTable", err)
	}

	o, err := New(db, testOutboxTable)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if o.Table() != testOutboxTable {
		t.Errorf("Table() = %q, want %q", o.Table(), testOutboxTable)
	}
	// DB() exists so a caller can assert the outbox lives on the SAME
	// connection its mutations run on.
	if o.DB() != db {
		t.Error("DB() does not return the handle New was given")
	}

	var nilOutbox *Outbox
	if nilOutbox.Table() != "" || nilOutbox.DB() != nil {
		t.Error("a nil Outbox must answer emptily rather than panic")
	}
}

// Every statement addresses the table the CALLER named. That is the whole
// difference between this package and the registry implementation it ports.
func TestStatementsAddressTheSuppliedTable(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	o, err := New(db, "tsm.my_outbox")
	if err != nil {
		t.Fatal(err)
	}
	for name, stmt := range map[string]string{
		"insert":  o.insertSQL,
		"claim":   o.claimSQL,
		"mark":    o.markSQL,
		"fail":    o.failSQL,
		"backlog": o.backlogSQL,
		"prune":   o.pruneSQL,
	} {
		if !strings.Contains(stmt, `"tsm"."my_outbox"`) {
			t.Errorf("the %s statement does not address the supplied table:\n%s", name, stmt)
		}
		if strings.Contains(stmt, "audit_outbox") {
			t.Errorf("the %s statement carries a hardcoded table name:\n%s", name, stmt)
		}
	}
}

func TestEnqueueRefusals(t *testing.T) {
	o, mock := newOutbox(t)
	mock.ExpectBegin()
	tx, err := o.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	mock.ExpectRollback()

	ctx := context.Background()
	var nilOutbox *Outbox

	tests := []struct {
		name   string
		run    func() error
		want   error
		saying string
	}{
		{
			name: "no outbox",
			run:  func() error { return nilOutbox.Enqueue(ctx, tx, &Intent{Action: "a.b"}) },
			want: ErrNoOutbox,
		},
		{
			name:   "no transaction",
			run:    func() error { return o.Enqueue(ctx, nil, &Intent{Action: "a.b"}) },
			want:   ErrNoOutbox,
			saying: "mutation's own transaction",
		},
		{
			name: "nil intent",
			run:  func() error { return o.Enqueue(ctx, tx, nil) },
			want: ErrIntentIncomplete,
		},
		{
			name:   "empty action",
			run:    func() error { return o.Enqueue(ctx, tx, &Intent{}) },
			want:   ErrIntentIncomplete,
			saying: "action is empty",
		},
		{
			name: "unencodable metadata",
			run: func() error {
				return o.Enqueue(ctx, tx, &Intent{Action: "a.b", Metadata: map[string]interface{}{"f": func() {}}})
			},
			want: ErrIntentIncomplete,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.saying != "" && !strings.Contains(err.Error(), tc.saying) {
				t.Errorf("error %q does not mention %q", err, tc.saying)
			}
		})
	}
	_ = tx.Rollback()
}

func TestEnqueueWritesTheIntentInTheCallersTransaction(t *testing.T) {
	o, mock := newOutbox(t)
	ctx := context.Background()

	actor := "11111111-1111-1111-1111-111111111111"
	target := "22222222-2222-2222-2222-222222222222"
	resource := "platform_admin"

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "registry"."audit_outbox"`)).
		WithArgs(
			sqlmock.AnyArg(), // event_id, minted here
			sqlmock.AnyArg(), // occurred_at, defaulted here
			"platform_admin.granted",
			actor,
			"actor@example.test",
			nil,
			resource,
			target,
			"203.0.113.7",
			[]byte(`{"target":"`+target+`"}`),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	tx, err := o.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	email := "actor@example.test"
	ip := "203.0.113.7"
	intent := &Intent{
		Action:       "platform_admin.granted",
		ActorUserID:  &actor,
		ActorEmail:   &email,
		ResourceType: &resource,
		ResourceID:   &target,
		IPAddress:    &ip,
		Metadata:     map[string]interface{}{"target": target},
	}
	if err := o.Enqueue(ctx, tx, intent); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// The id is chosen BEFORE the mutation commits and written back, because it
	// becomes the destination row's id — that is what makes redelivery
	// idempotent rather than merely retried.
	if intent.EventID == "" {
		t.Error("Enqueue did not mint an EventID")
	}
	if intent.OccurredAt.IsZero() {
		t.Error("Enqueue did not stamp OccurredAt")
	}
	if intent.OccurredAt.Location() != time.UTC {
		t.Errorf("OccurredAt is in %v, want UTC", intent.OccurredAt.Location())
	}
}

// A caller-supplied EventID is kept verbatim: it is the destination's primary
// key, so an outbox that reassigned it would break idempotence.
func TestEnqueueKeepsASuppliedEventID(t *testing.T) {
	o, mock := newOutbox(t)
	when := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "registry"."audit_outbox"`)).
		WithArgs("fixed-id", when, "a.b", nil, nil, nil, nil, nil, nil, nil).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	tx, err := o.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	intent := &Intent{EventID: "fixed-id", OccurredAt: when, Action: "a.b"}
	if err := o.Enqueue(context.Background(), tx, intent); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if intent.EventID != "fixed-id" {
		t.Errorf("EventID = %q, want it untouched", intent.EventID)
	}
}

func TestEnqueueWrapsTheExecFailure(t *testing.T) {
	o, mock := newOutbox(t)
	boom := errors.New("connection reset")

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "registry"."audit_outbox"`)).WillReturnError(boom)
	mock.ExpectRollback()

	tx, err := o.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	err = o.Enqueue(context.Background(), tx, &Intent{Action: "a.b"})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap the driver error", err)
	}
	if !strings.Contains(err.Error(), testOutboxTable) {
		t.Errorf("error %q does not name the outbox table", err)
	}
	_ = tx.Rollback()
}

// Writer must NEVER return nil, including from a misconfigured outbox: a nil
// writer is the one thing RequireIntentWriter refuses, so returning one would
// report "this call site forgot to audit" for what is really "audit is not
// wired up".
func TestWriterIsNeverNil(t *testing.T) {
	var nilOutbox *Outbox
	w := nilOutbox.Writer(&Intent{Action: "a.b"})
	if w == nil {
		t.Fatal("Writer returned nil from a nil Outbox")
	}
	if err := RequireIntentWriter(w); err != nil {
		t.Errorf("RequireIntentWriter rejected a non-nil writer: %v", err)
	}
	if err := w(context.Background(), nil); !errors.Is(err, ErrNoOutbox) {
		t.Errorf("the writer from a nil Outbox reported %v, want ErrNoOutbox", err)
	}
}

func TestWriterDelegatesToEnqueue(t *testing.T) {
	o, mock := newOutbox(t)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "registry"."audit_outbox"`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	tx, err := o.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	intent := &Intent{Action: "a.b"}
	if err := o.Writer(intent)(context.Background(), tx); err != nil {
		t.Fatalf("writer: %v", err)
	}
	if intent.EventID == "" {
		t.Error("the writer did not mint an EventID on the caller's intent")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestRequireIntentWriter(t *testing.T) {
	if err := RequireIntentWriter(nil); !errors.Is(err, ErrIntentRequired) {
		t.Fatalf("RequireIntentWriter(nil) = %v, want ErrIntentRequired", err)
	}
	called := false
	w := IntentWriter(func(context.Context, *sql.Tx) error { called = true; return nil })
	if err := RequireIntentWriter(w); err != nil {
		t.Fatalf("RequireIntentWriter(w) = %v, want nil", err)
	}
	if called {
		t.Error("RequireIntentWriter invoked the writer; it only checks presence")
	}
}

func TestBacklog(t *testing.T) {
	o, mock := newOutbox(t)
	oldest := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)

	mock.ExpectQuery(regexp.QuoteMeta(`FROM "registry"."audit_outbox"`)).
		WillReturnRows(sqlmock.NewRows([]string{"count", "failed", "oldest"}).AddRow(int64(4), int64(2), oldest))

	got, err := o.Backlog(context.Background())
	if err != nil {
		t.Fatalf("Backlog: %v", err)
	}
	want := Backlog{Pending: 4, Failed: 2, OldestPending: oldest}
	if got != want {
		t.Errorf("Backlog = %+v, want %+v", got, want)
	}
}

func TestBacklogEmptyAndUnconfigured(t *testing.T) {
	var nilOutbox *Outbox
	if _, err := nilOutbox.Backlog(context.Background()); !errors.Is(err, ErrNoOutbox) {
		t.Errorf("Backlog on a nil Outbox = %v, want ErrNoOutbox", err)
	}

	o, mock := newOutbox(t)
	mock.ExpectQuery(regexp.QuoteMeta(`FROM "registry"."audit_outbox"`)).
		WillReturnRows(sqlmock.NewRows([]string{"count", "failed", "oldest"}).AddRow(int64(0), int64(0), nil))
	got, err := o.Backlog(context.Background())
	if err != nil {
		t.Fatalf("Backlog: %v", err)
	}
	if got.Pending != 0 || !got.OldestPending.IsZero() {
		t.Errorf("Backlog = %+v, want an empty backlog with a zero OldestPending", got)
	}

	boom := errors.New("relation does not exist")
	mock.ExpectQuery(regexp.QuoteMeta(`FROM "registry"."audit_outbox"`)).WillReturnError(boom)
	if _, err := o.Backlog(context.Background()); !errors.Is(err, boom) {
		t.Errorf("Backlog = %v, want it to wrap the driver error", err)
	}
}

func TestPruneDelivered(t *testing.T) {
	o, mock := newOutbox(t)
	before := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	// A non-positive limit is defaulted rather than passed through: LIMIT 0
	// would prune nothing and look like a drained queue.
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "registry"."audit_outbox"`)).
		WithArgs(before, defaultPruneLimit).
		WillReturnResult(sqlmock.NewResult(0, 3))
	got, err := o.PruneDelivered(context.Background(), before, 0)
	if err != nil {
		t.Fatalf("PruneDelivered: %v", err)
	}
	if got != 3 {
		t.Errorf("pruned = %d, want 3", got)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "registry"."audit_outbox"`)).
		WithArgs(before, 25).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if _, err := o.PruneDelivered(context.Background(), before, 25); err != nil {
		t.Fatalf("PruneDelivered: %v", err)
	}

	// The pruner's statement may only ever reach DELIVERED rows.
	if !strings.Contains(o.pruneSQL, "delivered_at IS NOT NULL") {
		t.Errorf("the prune statement is not restricted to delivered rows:\n%s", o.pruneSQL)
	}

	var nilOutbox *Outbox
	if _, err := nilOutbox.PruneDelivered(context.Background(), before, 1); !errors.Is(err, ErrNoOutbox) {
		t.Errorf("PruneDelivered on a nil Outbox = %v, want ErrNoOutbox", err)
	}

	boom := errors.New("deadlock detected")
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "registry"."audit_outbox"`)).WillReturnError(boom)
	if _, err := o.PruneDelivered(context.Background(), before, 1); !errors.Is(err, boom) {
		t.Errorf("PruneDelivered = %v, want it to wrap the driver error", err)
	}
}

func expectDescribe(mock sqlmock.Sqlmock, schema string, columns []string) {
	mock.ExpectQuery(regexp.QuoteMeta(`current_setting('search_path'`)).
		WillReturnRows(sqlmock.NewRows([]string{"search_path"}).AddRow("registry,public"))
	rows := sqlmock.NewRows([]string{"nspname", "attname"})
	for _, c := range columns {
		rows.AddRow(schema, c)
	}
	mock.ExpectQuery(regexp.QuoteMeta(`to_regclass($1)`)).WillReturnRows(rows)
}

func TestOutboxVerify(t *testing.T) {
	t.Run("resolves and reports the qualified name", func(t *testing.T) {
		o, mock := newOutbox(t)
		expectDescribe(mock, "registry", outboxRequiredColumns)
		got, err := o.Verify(context.Background())
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if got != "registry.audit_outbox" {
			t.Errorf("Verify = %q, want registry.audit_outbox", got)
		}
	})

	t.Run("a table that resolves to nothing names the DDL to apply", func(t *testing.T) {
		o, mock := newOutbox(t)
		expectDescribe(mock, "registry", nil)
		_, err := o.Verify(context.Background())
		if !errors.Is(err, ErrOutboxShape) {
			t.Fatalf("Verify = %v, want ErrOutboxShape", err)
		}
		for _, want := range []string{"resolves to nothing", "OutboxDDL", "registry,public"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
	})

	t.Run("a missing column is named", func(t *testing.T) {
		o, mock := newOutbox(t)
		expectDescribe(mock, "registry", []string{"event_id", "action"})
		_, err := o.Verify(context.Background())
		if !errors.Is(err, ErrOutboxShape) {
			t.Fatalf("Verify = %v, want ErrOutboxShape", err)
		}
		// txid is the one that matters: without it the constraint trigger
		// cannot check the transaction, and the property is gone.
		if !strings.Contains(err.Error(), "txid") {
			t.Errorf("error %q does not name the missing txid column", err)
		}
	})

	t.Run("unconfigured", func(t *testing.T) {
		var nilOutbox *Outbox
		if _, err := nilOutbox.Verify(context.Background()); !errors.Is(err, ErrNoOutbox) {
			t.Errorf("Verify on a nil Outbox = %v, want ErrNoOutbox", err)
		}
	})

	t.Run("a failed probe is an error, never a default", func(t *testing.T) {
		o, mock := newOutbox(t)
		boom := errors.New("permission denied for schema pg_catalog")
		mock.ExpectQuery(regexp.QuoteMeta(`current_setting('search_path'`)).WillReturnError(boom)
		if _, err := o.Verify(context.Background()); !errors.Is(err, boom) {
			t.Errorf("Verify = %v, want the probe failure surfaced", err)
		}
	})
}
