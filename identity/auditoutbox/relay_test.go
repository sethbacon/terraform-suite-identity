package auditoutbox

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// recordingSink captures what the relay handed it and can be told to fail. It
// is mutex-guarded because Start delivers from its own goroutine.
type recordingSink struct {
	mu        sync.Mutex
	delivered []Intent
	err       error
}

func (s *recordingSink) Deliver(_ context.Context, intent Intent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.delivered = append(s.delivered, intent)
	return nil
}

func (s *recordingSink) snapshot() []Intent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Intent(nil), s.delivered...)
}

type recordingShipper struct {
	shipped []*Entry
	err     error
}

func (s *recordingShipper) Ship(_ context.Context, entry *Entry) error {
	s.shipped = append(s.shipped, entry)
	return s.err
}

var claimCols = []string{
	"event_id", "occurred_at", "action", "actor_user_id", "actor_email",
	"organization_id", "resource_type", "resource_id", "ip_address", "metadata", "attempts",
}

func claimRow(eventID string, metadata []byte, attempts int) []driver.Value {
	return []driver.Value{eventID, time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC), "platform_admin.granted",
		"actor-1", "actor@example.test", nil, "platform_admin", "target-1", "203.0.113.7", metadata, attempts}
}

func claimRows(rows ...[]driver.Value) *sqlmock.Rows {
	out := sqlmock.NewRows(claimCols)
	for _, r := range rows {
		out.AddRow(r...)
	}
	return out
}

func newRelay(t *testing.T, sink Sink, shipper Shipper, cfg RelayConfig) (*Relay, sqlmock.Sqlmock) {
	t.Helper()
	o, mock := newOutbox(t)
	return NewRelay(o, sink, shipper, cfg), mock
}

func captureLogs(t *testing.T) (*bytes.Buffer, *slog.Logger) {
	t.Helper()
	var buf bytes.Buffer
	return &buf, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// A misconfigured relay REFUSES TO START rather than idling: every intent the
// mutation paths write would otherwise accumulate forever with nothing to drain
// it, and the deployment would look healthy while its audit trail sat
// undelivered.
func TestRelayStartRefusesAMisconfiguration(t *testing.T) {
	t.Run("no outbox", func(t *testing.T) {
		r := NewRelay(nil, &recordingSink{}, nil, RelayConfig{})
		if err := r.Start(context.Background()); !errors.Is(err, ErrNoOutbox) {
			t.Fatalf("Start = %v, want ErrNoOutbox", err)
		}
	})
	t.Run("no sink", func(t *testing.T) {
		r, _ := newRelay(t, nil, nil, RelayConfig{})
		err := r.Start(context.Background())
		if err == nil {
			t.Fatal("Start succeeded with no sink")
		}
		if !strings.Contains(err.Error(), "never leave the outbox") {
			t.Errorf("error %q does not say what would go wrong", err)
		}
		if _, _, err := r.DeliverBatch(context.Background()); err == nil {
			t.Error("DeliverBatch succeeded with no sink")
		}
	})
	t.Run("no outbox on DeliverBatch", func(t *testing.T) {
		r := NewRelay(nil, &recordingSink{}, nil, RelayConfig{})
		if _, _, err := r.DeliverBatch(context.Background()); !errors.Is(err, ErrNoOutbox) {
			t.Fatalf("DeliverBatch = %v, want ErrNoOutbox", err)
		}
	})
}

func TestDeliverBatchOnAnEmptyQueue(t *testing.T) {
	sink := &recordingSink{}
	r, mock := newRelay(t, sink, nil, RelayConfig{BatchSize: 10})

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`FOR UPDATE SKIP LOCKED`)).WithArgs(10).
		WillReturnRows(sqlmock.NewRows(claimCols))
	// Committed rather than held open: an idle relay must not sit on a snapshot.
	mock.ExpectCommit()

	claimed, delivered, err := r.DeliverBatch(context.Background())
	if err != nil || claimed != 0 || delivered != 0 {
		t.Fatalf("DeliverBatch = (%d, %d, %v), want (0, 0, nil)", claimed, delivered, err)
	}
	if len(sink.delivered) != 0 {
		t.Error("the sink was called with nothing claimed")
	}
}

func TestDeliverBatchDeliversAndMarksInOneTransaction(t *testing.T) {
	sink := &recordingSink{}
	shipper := &recordingShipper{}
	r, mock := newRelay(t, sink, shipper, RelayConfig{BatchSize: 10})

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`FOR UPDATE SKIP LOCKED`)).WithArgs(10).
		WillReturnRows(claimRows(claimRow("e-1", []byte(`{"note":"x"}`), 0)))
	mock.ExpectExec(regexp.QuoteMeta(`SET delivered_at = now()`)).WithArgs("e-1").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	claimed, delivered, err := r.DeliverBatch(context.Background())
	if err != nil || claimed != 1 || delivered != 1 {
		t.Fatalf("DeliverBatch = (%d, %d, %v), want (1, 1, nil)", claimed, delivered, err)
	}
	if len(sink.delivered) != 1 || sink.delivered[0].EventID != "e-1" {
		t.Fatalf("the sink received %+v, want one intent e-1", sink.delivered)
	}
	if got := sink.delivered[0].Metadata["note"]; got != "x" {
		t.Errorf("delivered metadata = %v, want the claimed value", sink.delivered[0].Metadata)
	}

	// The stable event id travels with the shipped entry so a SIEM can collapse
	// a redelivery instead of counting the same event twice.
	if len(shipper.shipped) != 1 {
		t.Fatalf("shipped %d entries, want 1", len(shipper.shipped))
	}
	entry := shipper.shipped[0]
	if entry.EventID != "e-1" || entry.Action != "platform_admin.granted" ||
		entry.UserID != "actor-1" || entry.ActorEmail != "actor@example.test" ||
		entry.ResourceID != "target-1" || entry.IPAddress != "203.0.113.7" {
		t.Errorf("shipped entry = %+v, does not carry the intent", entry)
	}
}

// Unreadable metadata must not cost the record. The who/what/when is the part
// that matters; the detail is replaced with an explanation.
func TestDeliverBatchKeepsTheRecordWhenMetadataIsUnreadable(t *testing.T) {
	sink := &recordingSink{}
	r, mock := newRelay(t, sink, nil, RelayConfig{BatchSize: 10})

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`FOR UPDATE SKIP LOCKED`)).
		WillReturnRows(claimRows(claimRow("e-1", []byte(`{not json`), 0)))
	mock.ExpectExec(regexp.QuoteMeta(`SET delivered_at = now()`)).WithArgs("e-1").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if _, delivered, err := r.DeliverBatch(context.Background()); err != nil || delivered != 1 {
		t.Fatalf("DeliverBatch = (%d, %v), want (1, nil)", delivered, err)
	}
	if _, ok := sink.delivered[0].Metadata["metadata_unreadable"]; !ok {
		t.Errorf("delivered metadata = %v, want the unreadable-blob explanation", sink.delivered[0].Metadata)
	}
}

// A single intent that fails does not abort the batch: its failure is recorded
// on its own row, it stays undelivered, and the rest proceeds. Aborting instead
// would let one poisoned record block every audit entry behind it.
func TestDeliverBatchRetainsAFailedIntentAndCommitsTheRest(t *testing.T) {
	boom := errors.New("destination unreachable")
	sink := &recordingSink{err: boom}
	buf, logger := captureLogs(t)
	r, mock := newRelay(t, sink, nil, RelayConfig{BatchSize: 10, Logger: logger})

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`FOR UPDATE SKIP LOCKED`)).
		WillReturnRows(claimRows(claimRow("e-1", nil, 2)))
	mock.ExpectExec(regexp.QuoteMeta(`SET attempts = attempts + 1, last_error = $2`)).
		WithArgs("e-1", boom.Error()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	var failures int
	r.cfg.Observer.DeliveryFailures = func(n int) { failures = n }

	claimed, delivered, err := r.DeliverBatch(context.Background())
	if err != nil || claimed != 1 || delivered != 0 {
		t.Fatalf("DeliverBatch = (%d, %d, %v), want (1, 0, nil)", claimed, delivered, err)
	}
	if failures != 1 {
		t.Errorf("observer saw %d failures, want 1", failures)
	}
	// The reason is kept AND said out loud: an intent that stops delivering
	// with no explanation is a backlog nobody can act on.
	if !strings.Contains(buf.String(), "intent retained for retry") ||
		!strings.Contains(buf.String(), boom.Error()) {
		t.Errorf("the failure was not logged with its cause:\n%s", buf.String())
	}
}

// Shipping is external visibility, not the audit trail. Holding the intent for
// a broken SIEM would grow the backlog without protecting the record.
func TestAShippingFailureDoesNotRetainTheIntent(t *testing.T) {
	sink := &recordingSink{}
	shipper := &recordingShipper{err: errors.New("siem 503")}
	r, mock := newRelay(t, sink, shipper, RelayConfig{BatchSize: 10})

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`FOR UPDATE SKIP LOCKED`)).
		WillReturnRows(claimRows(claimRow("e-1", nil, 0)))
	mock.ExpectExec(regexp.QuoteMeta(`SET delivered_at = now()`)).WithArgs("e-1").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	var shipFailures int
	r.cfg.Observer.ShipFailures = func(n int) { shipFailures += n }

	if _, delivered, err := r.DeliverBatch(context.Background()); err != nil || delivered != 1 {
		t.Fatalf("DeliverBatch = (%d, %v), want (1, nil) — a shipping failure must not hold the record",
			delivered, err)
	}
	if shipFailures != 1 {
		t.Errorf("observer saw %d ship failures, want 1", shipFailures)
	}
}

func TestDeliverBatchSurfacesDatabaseFailures(t *testing.T) {
	t.Run("claim fails", func(t *testing.T) {
		boom := errors.New("relation does not exist")
		r, mock := newRelay(t, &recordingSink{}, nil, RelayConfig{BatchSize: 10})
		mock.ExpectBegin()
		mock.ExpectQuery(regexp.QuoteMeta(`FOR UPDATE SKIP LOCKED`)).WillReturnError(boom)
		mock.ExpectRollback()
		if _, _, err := r.DeliverBatch(context.Background()); !errors.Is(err, boom) {
			t.Fatalf("DeliverBatch = %v, want the claim failure", err)
		}
	})

	t.Run("mark fails", func(t *testing.T) {
		boom := errors.New("deadlock detected")
		r, mock := newRelay(t, &recordingSink{}, nil, RelayConfig{BatchSize: 10})
		mock.ExpectBegin()
		mock.ExpectQuery(regexp.QuoteMeta(`FOR UPDATE SKIP LOCKED`)).
			WillReturnRows(claimRows(claimRow("e-1", nil, 0)))
		mock.ExpectExec(regexp.QuoteMeta(`SET delivered_at = now()`)).WillReturnError(boom)
		mock.ExpectRollback()
		if _, delivered, err := r.DeliverBatch(context.Background()); !errors.Is(err, boom) || delivered != 0 {
			t.Fatalf("DeliverBatch = (%d, %v), want (0, the mark failure)", delivered, err)
		}
	})

	// NOTHING WAS MARKED. Every intent in the batch is still pending and will
	// be claimed again — the crash contract, in its recoverable form.
	t.Run("commit fails", func(t *testing.T) {
		boom := errors.New("server closed the connection unexpectedly")
		r, mock := newRelay(t, &recordingSink{}, nil, RelayConfig{BatchSize: 10})
		mock.ExpectBegin()
		mock.ExpectQuery(regexp.QuoteMeta(`FOR UPDATE SKIP LOCKED`)).
			WillReturnRows(claimRows(claimRow("e-1", nil, 0)))
		mock.ExpectExec(regexp.QuoteMeta(`SET delivered_at = now()`)).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit().WillReturnError(boom)
		claimed, delivered, err := r.DeliverBatch(context.Background())
		if !errors.Is(err, boom) || claimed != 1 || delivered != 0 {
			t.Fatalf("DeliverBatch = (%d, %d, %v), want (1, 0, the commit failure)", claimed, delivered, err)
		}
	})

	t.Run("begin fails", func(t *testing.T) {
		boom := errors.New("too many connections")
		r, mock := newRelay(t, &recordingSink{}, nil, RelayConfig{BatchSize: 10})
		mock.ExpectBegin().WillReturnError(boom)
		if _, _, err := r.DeliverBatch(context.Background()); !errors.Is(err, boom) {
			t.Fatalf("DeliverBatch = %v, want the begin failure", err)
		}
	})
}

// A full batch means there may be more; a short one means the queue is drained
// (or the rest is locked by another replica).
func TestRunCycleDrainsUntilAShortBatch(t *testing.T) {
	sink := &recordingSink{}
	r, mock := newRelay(t, sink, nil, RelayConfig{BatchSize: 2, RetainDelivered: -1, BacklogWarn: -1})

	// Batch 1: full.
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`FOR UPDATE SKIP LOCKED`)).WithArgs(2).
		WillReturnRows(claimRows(claimRow("e-1", nil, 0), claimRow("e-2", nil, 0)))
	mock.ExpectExec(regexp.QuoteMeta(`SET delivered_at = now()`)).WithArgs("e-1").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`SET delivered_at = now()`)).WithArgs("e-2").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	// Batch 2: short, so the cycle stops.
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`FOR UPDATE SKIP LOCKED`)).WithArgs(2).
		WillReturnRows(claimRows(claimRow("e-3", nil, 0)))
	mock.ExpectExec(regexp.QuoteMeta(`SET delivered_at = now()`)).WithArgs("e-3").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	// Then the backlog read. Pruning is disabled by RetainDelivered: -1.
	mock.ExpectQuery(regexp.QuoteMeta(`FROM "registry"."audit_outbox"`)).
		WillReturnRows(sqlmock.NewRows([]string{"count", "failed", "oldest"}).AddRow(int64(0), int64(0), nil))

	var deliveredTotal int
	var seenBacklog *Backlog
	r.cfg.Observer.Delivered = func(n int) { deliveredTotal += n }
	r.cfg.Observer.Backlog = func(b Backlog) { seenBacklog = &b }

	r.RunCycle(context.Background())

	if deliveredTotal != 3 {
		t.Errorf("observer saw %d delivered, want 3", deliveredTotal)
	}
	if len(sink.delivered) != 3 {
		t.Errorf("the sink received %d intents, want 3", len(sink.delivered))
	}
	if seenBacklog == nil {
		t.Error("the cycle did not report the backlog; an unbounded queue must at least be visible")
	}
}

// The backlog cannot be bounded by discarding it, so it is bounded by being
// LOUD: an ERROR line naming the depth and the age of the oldest intent.
func TestRunCycleShoutsAboutABacklog(t *testing.T) {
	buf, logger := captureLogs(t)
	r, mock := newRelay(t, &recordingSink{}, nil,
		RelayConfig{BatchSize: 10, BacklogWarn: 2, RetainDelivered: -1, Logger: logger})

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`FOR UPDATE SKIP LOCKED`)).WillReturnRows(sqlmock.NewRows(claimCols))
	mock.ExpectCommit()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM "registry"."audit_outbox"`)).
		WillReturnRows(sqlmock.NewRows([]string{"count", "failed", "oldest"}).
			AddRow(int64(5), int64(4), time.Now().Add(-90*time.Second)))

	r.RunCycle(context.Background())

	log := buf.String()
	if !strings.Contains(log, "level=ERROR") || !strings.Contains(log, "backlog is not draining") {
		t.Fatalf("a growing backlog did not produce an ERROR line:\n%s", log)
	}
	for _, want := range []string{"pending=5", "failed_at_least_once=4", "threshold=2", "oldest_age_seconds=90"} {
		if !strings.Contains(log, want) {
			t.Errorf("the alarm line does not carry %q:\n%s", want, log)
		}
	}
}

func TestRunCyclePrunesDeliveredHistory(t *testing.T) {
	r, mock := newRelay(t, &recordingSink{}, nil,
		RelayConfig{BatchSize: 5, BacklogWarn: -1, RetainDelivered: time.Hour})

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`FOR UPDATE SKIP LOCKED`)).WillReturnRows(sqlmock.NewRows(claimCols))
	mock.ExpectCommit()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM "registry"."audit_outbox"`)).
		WillReturnRows(sqlmock.NewRows([]string{"count", "failed", "oldest"}).AddRow(int64(0), int64(0), nil))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "registry"."audit_outbox"`)).
		WithArgs(sqlmock.AnyArg(), 5*defaultRelayMaxBatches).
		WillReturnResult(sqlmock.NewResult(0, 7))

	var pruned int64
	r.cfg.Observer.Pruned = func(n int64) { pruned = n }
	r.RunCycle(context.Background())

	if pruned != 7 {
		t.Errorf("observer saw %d pruned, want 7", pruned)
	}
}

func TestRelayConfigDefaults(t *testing.T) {
	zero := RelayConfig{}
	if zero.pollInterval() != defaultRelayInterval {
		t.Errorf("pollInterval = %v, want %v", zero.pollInterval(), defaultRelayInterval)
	}
	if zero.batchSize() != defaultRelayBatchSize {
		t.Errorf("batchSize = %d, want %d", zero.batchSize(), defaultRelayBatchSize)
	}
	if zero.backlogWarn() != defaultRelayBacklogWarn {
		t.Errorf("backlogWarn = %d, want %d", zero.backlogWarn(), defaultRelayBacklogWarn)
	}
	if zero.retainDelivered() != defaultRelayDeliveredRetain {
		t.Errorf("retainDelivered = %v, want %v", zero.retainDelivered(), defaultRelayDeliveredRetain)
	}
	if zero.logger() != slog.Default() {
		t.Error("logger() does not fall back to slog.Default()")
	}

	// Negative is not "unset": it is how an operator disables the alarm and
	// keeps the outbox as a delivery ledger for reconciliation.
	set := RelayConfig{PollInterval: time.Second, BatchSize: 3, BacklogWarn: -1, RetainDelivered: -1}
	if set.backlogWarn() != -1 || set.retainDelivered() != -1 || set.batchSize() != 3 ||
		set.pollInterval() != time.Second {
		t.Errorf("explicit configuration was overridden by the defaults: %+v", set)
	}
}

func TestRelayNameAndStop(t *testing.T) {
	r := NewRelay(nil, nil, nil, RelayConfig{})
	if r.Name() != RelayJobName {
		t.Errorf("Name() = %q, want %q", r.Name(), RelayJobName)
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

// Start runs one cycle immediately and then on the ticker, and returns on Stop.
func TestRelayStartRunsUntilStopped(t *testing.T) {
	sink := &recordingSink{}
	_, logger := captureLogs(t)
	r, mock := newRelay(t, sink, nil,
		RelayConfig{BatchSize: 10, PollInterval: time.Hour, BacklogWarn: -1, RetainDelivered: -1, Logger: logger})

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`FOR UPDATE SKIP LOCKED`)).
		WillReturnRows(claimRows(claimRow("e-1", nil, 0)))
	mock.ExpectExec(regexp.QuoteMeta(`SET delivered_at = now()`)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM "registry"."audit_outbox"`)).
		WillReturnRows(sqlmock.NewRows([]string{"count", "failed", "oldest"}).AddRow(int64(0), int64(0), nil))

	done := make(chan error, 1)
	go func() { done <- r.Start(context.Background()) }()

	deadline := time.After(5 * time.Second)
	for len(sink.snapshot()) == 0 {
		select {
		case <-deadline:
			t.Fatal("the relay never ran a cycle")
		case <-time.After(time.Millisecond):
		}
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned %v, want nil after Stop", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

// A cancelled context ends the loop the same way Stop does.
func TestRelayStartReturnsOnContextCancellation(t *testing.T) {
	_, logger := captureLogs(t)
	r, mock := newRelay(t, &recordingSink{}, nil,
		RelayConfig{BatchSize: 10, PollInterval: time.Hour, BacklogWarn: -1, RetainDelivered: -1, Logger: logger})

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`FOR UPDATE SKIP LOCKED`)).WillReturnRows(sqlmock.NewRows(claimCols))
	mock.ExpectCommit()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM "registry"."audit_outbox"`)).
		WillReturnRows(sqlmock.NewRows([]string{"count", "failed", "oldest"}).AddRow(int64(0), int64(0), nil))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Start(ctx) }()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned %v, want nil after cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after its context was cancelled")
	}
}

// A cycle that cannot read the backlog, or cannot prune, says so and carries on:
// neither is a reason to stop delivering.
func TestRunCycleSurvivesObservationFailures(t *testing.T) {
	buf, logger := captureLogs(t)
	r, mock := newRelay(t, &recordingSink{}, nil,
		RelayConfig{BatchSize: 10, RetainDelivered: time.Hour, Logger: logger})

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`FOR UPDATE SKIP LOCKED`)).WillReturnError(errors.New("claim exploded"))
	mock.ExpectRollback()
	mock.ExpectQuery(regexp.QuoteMeta(`FROM "registry"."audit_outbox"`)).WillReturnError(errors.New("backlog exploded"))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "registry"."audit_outbox"`)).WillReturnError(errors.New("prune exploded"))

	r.RunCycle(context.Background())

	log := buf.String()
	for _, want := range []string{"delivery cycle failed", "failed to read backlog", "prune failed"} {
		if !strings.Contains(log, want) {
			t.Errorf("the cycle did not report %q:\n%s", want, log)
		}
	}
}
