package auditoutbox

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jackc/pgx/v5/pgconn"
)

// The two destination shapes this package must work against, both real.
//
// wideAuditLogs is identity.audit_logs after identity migration 000007. It
// carries actor_email.
//
// narrowAuditLogs is what `audit_logs` resolves to in registry's DEFAULT
// topology: its own public.audit_logs from migration 000001, which has never had
// actor_email and does not get one from the identity chain either. Every write
// through the shared writer fails there with 42703 — registry #864, still open —
// and this package must deliver anyway.
var (
	wideAuditLogs = []string{
		"id", "user_id", "organization_id", "action", "resource_type",
		"resource_id", "metadata", "ip_address", "created_at", "actor_email",
	}
	narrowAuditLogs = []string{
		"id", "user_id", "organization_id", "action", "resource_type",
		"resource_id", "metadata", "ip_address", "created_at",
	}
)

func newSink(t *testing.T) (*TableSink, sqlmock.Sqlmock) {
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
	s, err := NewTableSink(db, "registry.audit_logs")
	if err != nil {
		t.Fatalf("NewTableSink: %v", err)
	}
	return s, mock
}

func sampleIntent() Intent {
	actor := "11111111-1111-1111-1111-111111111111"
	email := "actor@example.test"
	org := "33333333-3333-3333-3333-333333333333"
	resource := "platform_admin"
	target := "22222222-2222-2222-2222-222222222222"
	ip := "203.0.113.7"
	return Intent{
		EventID:        "44444444-4444-4444-4444-444444444444",
		OccurredAt:     time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC),
		Action:         "platform_admin.granted",
		ActorUserID:    &actor,
		ActorEmail:     &email,
		OrganizationID: &org,
		ResourceType:   &resource,
		ResourceID:     &target,
		IPAddress:      &ip,
		Metadata:       map[string]interface{}{"note": "on-call"},
	}
}

func TestNewTableSink(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if _, err := NewTableSink(nil, "audit_logs"); !errors.Is(err, ErrDestinationShape) {
		t.Errorf("NewTableSink(nil db) = %v, want ErrDestinationShape", err)
	}
	if _, err := NewTableSink(db, "audit logs"); !errors.Is(err, ErrInvalidTable) {
		t.Errorf("NewTableSink(bad name) = %v, want ErrInvalidTable", err)
	}
	s, err := NewTableSink(db, "registry.audit_logs")
	if err != nil {
		t.Fatal(err)
	}
	if s.Table() != "registry.audit_logs" {
		t.Errorf("Table() = %q, want registry.audit_logs", s.Table())
	}
	var nilSink *TableSink
	if nilSink.Table() != "" {
		t.Error("a nil TableSink must answer emptily rather than panic")
	}
	if err := nilSink.Deliver(context.Background(), sampleIntent()); !errors.Is(err, ErrDestinationShape) {
		t.Errorf("Deliver on a nil sink = %v, want ErrDestinationShape", err)
	}
	if _, err := nilSink.Verify(context.Background()); !errors.Is(err, ErrDestinationShape) {
		t.Errorf("Verify on a nil sink = %v, want ErrDestinationShape", err)
	}
}

// Without a stable id there is no idempotence, only duplicates.
func TestDeliverRefusesAnIntentWithNoEventID(t *testing.T) {
	s, _ := newSink(t)
	intent := sampleIntent()
	intent.EventID = ""
	if err := s.Deliver(context.Background(), intent); !errors.Is(err, ErrIntentIncomplete) {
		t.Fatalf("Deliver = %v, want ErrIntentIncomplete", err)
	}
}

func TestDeliverAgainstAWideDestination(t *testing.T) {
	s, mock := newSink(t)
	intent := sampleIntent()

	expectDescribe(mock, "registry", wideAuditLogs)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "registry"."audit_logs" ("id", "user_id", "organization_id", `+
		`"action", "resource_type", "resource_id", "metadata", "ip_address", "created_at", "actor_email")`)).
		WithArgs(intent.EventID, *intent.ActorUserID, *intent.OrganizationID, intent.Action,
			*intent.ResourceType, *intent.ResourceID, []byte(`{"note":"on-call"}`), *intent.IPAddress,
			intent.OccurredAt, *intent.ActorEmail).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := s.Deliver(context.Background(), intent); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	// ON CONFLICT (id) DO NOTHING is the idempotence: an at-least-once
	// redelivery must update nothing and report success.
	if !strings.Contains(s.stmt, `ON CONFLICT (id) DO NOTHING`) {
		t.Errorf("the delivery statement is not idempotent:\n%s", s.stmt)
	}
}

// THE PORTED LESSON (registry #864). The destination is the pre-000007 shape,
// so a sink that assumed a schema version would fail with 42703 on every
// attempt and turn a per-request failure into a permanently undelivered
// backlog. It probes instead, and delivers.
func TestDeliverAgainstANarrowDestinationDropsWhatItCannotStore(t *testing.T) {
	s, mock := newSink(t)
	intent := sampleIntent()

	expectDescribe(mock, "public", narrowAuditLogs)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "registry"."audit_logs" ("id", "user_id", "organization_id", `+
		`"action", "resource_type", "resource_id", "metadata", "ip_address", "created_at")`)).
		WithArgs(intent.EventID, *intent.ActorUserID, *intent.OrganizationID, intent.Action,
			*intent.ResourceType, *intent.ResourceID, []byte(`{"note":"on-call"}`), *intent.IPAddress,
			intent.OccurredAt).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := s.Deliver(context.Background(), intent); err != nil {
		t.Fatalf("Deliver against the default-topology audit_logs: %v", err)
	}
	if strings.Contains(s.stmt, "actor_email") {
		t.Errorf("the delivery statement writes a column this destination does not have:\n%s", s.stmt)
	}
}

// A nil Metadata is SQL NULL, not the string "null".
func TestDeliverSendsNullForAbsentValues(t *testing.T) {
	s, mock := newSink(t)
	intent := Intent{EventID: "e-1", Action: "a.b", OccurredAt: time.Now().UTC()}

	expectDescribe(mock, "registry", wideAuditLogs)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "registry"."audit_logs"`)).
		WithArgs("e-1", nil, nil, "a.b", nil, nil, nil, nil, intent.OccurredAt, nil).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := s.Deliver(context.Background(), intent); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
}

// id and action are required. Without them a delivered row would be neither
// identifiable nor meaningful, so the intent stays in the backlog rather than
// being written as something that is not an audit record.
func TestDeliverRefusesADestinationMissingTheRequiredColumns(t *testing.T) {
	for _, tc := range []struct {
		name    string
		columns []string
		want    string
	}{
		{name: "no id", columns: []string{"action", "created_at"}, want: "[id]"},
		{name: "no action", columns: []string{"id", "created_at"}, want: "[action]"},
		{name: "neither", columns: []string{"created_at"}, want: "[id action]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, mock := newSink(t)
			expectDescribe(mock, "registry", tc.columns)
			err := s.Deliver(context.Background(), sampleIntent())
			if !errors.Is(err, ErrDestinationShape) {
				t.Fatalf("Deliver = %v, want ErrDestinationShape", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %s", err, tc.want)
			}
		})
	}
}

func TestDeliverRefusesADestinationThatResolvesToNothing(t *testing.T) {
	s, mock := newSink(t)
	expectDescribe(mock, "registry", nil)
	err := s.Deliver(context.Background(), sampleIntent())
	if !errors.Is(err, ErrDestinationShape) {
		t.Fatalf("Deliver = %v, want ErrDestinationShape", err)
	}
	if !strings.Contains(err.Error(), "resolves to nothing") {
		t.Errorf("error %q does not say the table is absent", err)
	}
}

// The probe is one round trip per process, not per delivery.
func TestDeliverProbesOnceAndReusesThePlan(t *testing.T) {
	s, mock := newSink(t)
	intent := sampleIntent()

	expectDescribe(mock, "registry", wideAuditLogs)
	for i := 0; i < 3; i++ {
		mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "registry"."audit_logs"`)).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
	for i := 0; i < 3; i++ {
		if err := s.Deliver(context.Background(), intent); err != nil {
			t.Fatalf("Deliver %d: %v", i+1, err)
		}
	}
}

// A FAILED probe is not cached. Registry caches its probe under a sync.Once
// that also swallows the failure, so one transient catalogue error there
// silently narrows every subsequent delivery for the life of the process.
func TestAFailedProbeIsNotCached(t *testing.T) {
	s, mock := newSink(t)
	boom := errors.New("canceling statement due to statement timeout")

	mock.ExpectQuery(regexp.QuoteMeta(`current_setting('search_path'`)).WillReturnError(boom)
	if err := s.Deliver(context.Background(), sampleIntent()); !errors.Is(err, boom) {
		t.Fatalf("Deliver = %v, want the probe failure surfaced rather than a guessed shape", err)
	}

	expectDescribe(mock, "registry", wideAuditLogs)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "registry"."audit_logs"`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := s.Deliver(context.Background(), sampleIntent()); err != nil {
		t.Fatalf("the retry after a transient probe failure: %v", err)
	}
	if !strings.Contains(s.stmt, "actor_email") {
		t.Error("the retry re-probed but did not pick up the full column set")
	}
}

// 42703 undefined_column means the destination changed shape under a cached
// plan — an app migration applied while this process was running. The plan is
// discarded so the next attempt can actually succeed instead of failing
// identically until a restart.
func TestAnUndefinedColumnInvalidatesTheCachedPlan(t *testing.T) {
	s, mock := newSink(t)
	intent := sampleIntent()

	expectDescribe(mock, "registry", wideAuditLogs)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "registry"."audit_logs"`)).
		WillReturnError(&pgconn.PgError{Code: "42703", Message: `column "actor_email" of relation "audit_logs" does not exist`})
	if err := s.Deliver(context.Background(), intent); err == nil {
		t.Fatal("Deliver succeeded against a destination that rejected the column")
	}
	if s.stmt != "" {
		t.Fatal("the cached plan survived a 42703; every retry would fail identically until a restart")
	}

	expectDescribe(mock, "public", narrowAuditLogs)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "registry"."audit_logs"`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := s.Deliver(context.Background(), intent); err != nil {
		t.Fatalf("the retry after the destination changed shape: %v", err)
	}
	if strings.Contains(s.stmt, "actor_email") {
		t.Error("the re-probe did not pick up the narrowed destination")
	}
}

// Any other driver error leaves the plan alone: re-probing on every transient
// failure would spend a catalogue round trip per retry for no gain.
func TestAnOrdinaryDeliveryFailureKeepsThePlan(t *testing.T) {
	s, mock := newSink(t)
	expectDescribe(mock, "registry", wideAuditLogs)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "registry"."audit_logs"`)).
		WillReturnError(&pgconn.PgError{Code: "40001", Message: "could not serialize access"})
	if err := s.Deliver(context.Background(), sampleIntent()); err == nil {
		t.Fatal("Deliver succeeded against a failing destination")
	}
	if s.stmt == "" {
		t.Error("a serialization failure discarded the cached plan")
	}
}

func TestSinkVerifyReportsTheResolvedName(t *testing.T) {
	s, mock := newSink(t)
	expectDescribe(mock, "public", narrowAuditLogs)
	got, err := s.Verify(context.Background())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// The name is the point: the table is app-owned, and an unqualified name is
	// placed by the connection's search_path.
	if got != "public.audit_logs" {
		t.Errorf("Verify = %q, want public.audit_logs", got)
	}

	s2, mock2 := newSink(t)
	expectDescribe(mock2, "registry", []string{"created_at"})
	if _, err := s2.Verify(context.Background()); !errors.Is(err, ErrDestinationShape) {
		t.Errorf("Verify against an unusable destination = %v, want ErrDestinationShape", err)
	}
}
