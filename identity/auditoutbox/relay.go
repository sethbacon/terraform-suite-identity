// relay.go delivers the transactional outbox to the app's audit table and to
// any configured Shipper.
//
// # The crash contract
//
// One cycle is: claim a batch inside a transaction on the outbox connection,
// deliver each intent, mark it delivered, commit. The mark and the claim share
// that transaction, so a process that dies at any point before the commit leaves
// every intent in the cycle still undelivered — and the next relay (this process
// after a restart, or another replica) claims them again. Nothing is lost by a
// crash; the cost of one is a redelivery, which the sink absorbs by keying the
// destination row on the intent's own EventID (sink.go).
//
// Delivery is therefore at-least-once in transport and exactly-once in effect.
package auditoutbox

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity/internal/safeloop"
)

// Relay defaults. Deliberately unexcitable: these are privileged-mutation
// records, a handful an hour in a busy deployment, and a tight poll would spend
// far more on empty scans than the latency is worth.
const (
	defaultRelayInterval        = 10 * time.Second
	defaultRelayBatchSize       = 100
	defaultRelayMaxBatches      = 10
	defaultRelayBacklogWarn     = 100
	defaultRelayDeliveredRetain = 7 * 24 * time.Hour
)

// Observer publishes what one relay cycle did, so the host can expose it as
// metrics. Every field is optional and a nil field is simply not called: this
// module ships no metrics registry of its own and must not pick one for its two
// consuming applications.
//
// Backlog is the one that matters. The undelivered depth cannot be bounded by
// discarding it — that would throw away the records the outbox exists to keep —
// so it is bounded by being VISIBLE instead.
type Observer struct {
	Backlog          func(Backlog)
	Delivered        func(n int)
	DeliveryFailures func(n int)
	ShipFailures     func(n int)
	Pruned           func(n int64)
}

// RelayConfig tunes the relay. The zero value is valid and means the defaults
// above.
type RelayConfig struct {
	// PollInterval is how often the relay looks for undelivered intents.
	PollInterval time.Duration
	// BatchSize is how many intents one claim takes.
	BatchSize int
	// BacklogWarn is the undelivered depth at which the relay starts logging at
	// ERROR. Zero means the default; negative disables the alarm.
	BacklogWarn int64
	// RetainDelivered is how long a delivered intent is kept before pruning.
	// The outbox is a delivery queue, not a second copy of the audit trail —
	// the destination table is the record, and its retention is the app's.
	// Negative disables pruning, which is how an operator keeps the outbox as a
	// delivery ledger for reconciliation.
	RetainDelivered time.Duration
	// Logger receives the relay's lines. Nil means slog.Default(), read at call
	// time so a host that installs its handler after importing this module
	// still gets them.
	Logger *slog.Logger
	// Observer receives cycle outcomes for the host's metrics.
	Observer Observer
}

func (c RelayConfig) pollInterval() time.Duration {
	if c.PollInterval <= 0 {
		return defaultRelayInterval
	}
	return c.PollInterval
}

func (c RelayConfig) batchSize() int {
	if c.BatchSize <= 0 {
		return defaultRelayBatchSize
	}
	return c.BatchSize
}

func (c RelayConfig) backlogWarn() int64 {
	if c.BacklogWarn == 0 {
		return defaultRelayBacklogWarn
	}
	return c.BacklogWarn
}

func (c RelayConfig) retainDelivered() time.Duration {
	if c.RetainDelivered == 0 {
		return defaultRelayDeliveredRetain
	}
	return c.RetainDelivered
}

func (c RelayConfig) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

// Relay drains the audit outbox.
type Relay struct {
	outbox  *Outbox
	sink    Sink
	shipper Shipper
	cfg     RelayConfig

	stopChan chan struct{}
}

// NewRelay constructs a Relay. shipper may be nil when no external shipping is
// configured; sink may not be, since it is the durable destination.
func NewRelay(outbox *Outbox, sink Sink, shipper Shipper, cfg RelayConfig) *Relay {
	return &Relay{
		outbox:   outbox,
		sink:     sink,
		shipper:  shipper,
		cfg:      cfg,
		stopChan: make(chan struct{}),
	}
}

// RelayJobName is the stable identifier this job uses in log lines.
const RelayJobName = "audit-outbox-relay"

// Name returns the job name used in logs.
func (r *Relay) Name() string { return RelayJobName }

// Start runs one cycle immediately, then on a ticker, until Stop or ctx.
//
// A misconfigured relay REFUSES TO START rather than idling: with no outbox or
// no sink, every intent written by the mutation paths would accumulate forever
// with nothing to drain it, and the deployment would look healthy while its
// audit trail sat undelivered.
//
// Run it in a goroutine the host owns. Each cycle runs inside safeloop.Guard, so
// a panic in one cycle costs that cycle rather than the host's process.
func (r *Relay) Start(ctx context.Context) error {
	if r.outbox == nil || r.outbox.db == nil {
		return ErrNoOutbox
	}
	if r.sink == nil {
		return errors.New("identity/auditoutbox: relay has no sink; audit intents would never leave the outbox")
	}

	log := r.cfg.logger()
	log.Info("audit outbox relay: started",
		"outbox", r.outbox.Table(), "poll_interval", r.cfg.pollInterval(), "batch_size", r.cfg.batchSize())

	safeloop.Guard(RelayJobName, func() { r.RunCycle(ctx) })

	ticker := time.NewTicker(r.cfg.pollInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			safeloop.Guard(RelayJobName, func() { r.RunCycle(ctx) })
		case <-r.stopChan:
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

// Stop signals the relay to exit. Safe to call more than once.
func (r *Relay) Stop() error {
	select {
	case <-r.stopChan:
	default:
		close(r.stopChan)
	}
	return nil
}

// RunCycle drains up to defaultRelayMaxBatches batches, then reports the backlog
// and prunes delivered history.
//
// The batch cap bounds one cycle's work so a large backlog cannot starve
// shutdown or hold a transaction open indefinitely; what it does not drain is
// picked up on the next tick.
//
// Exported so a test — and an operator, through a one-shot invocation — can
// drive delivery deterministically instead of racing the ticker.
func (r *Relay) RunCycle(ctx context.Context) {
	log := r.cfg.logger()
	for i := 0; i < defaultRelayMaxBatches; i++ {
		claimed, delivered, err := r.DeliverBatch(ctx)
		if err != nil {
			log.Error("audit outbox relay: delivery cycle failed", "error", err)
			break
		}
		if delivered > 0 && r.cfg.Observer.Delivered != nil {
			r.cfg.Observer.Delivered(delivered)
		}
		// A short batch means the queue is drained (or the rest is locked by
		// another replica); either way there is nothing more to do this cycle.
		if claimed < r.cfg.batchSize() {
			break
		}
	}

	r.observeBacklog(ctx)
	r.prune(ctx)
}

// DeliverBatch runs exactly one claim/deliver/commit cycle and reports how many
// intents were claimed and how many of those were delivered.
//
// A single intent that fails to deliver does not abort the batch: its failure is
// recorded on its own row, it stays undelivered, and the rest of the batch
// proceeds. Aborting instead would let one poisoned record block every audit
// entry behind it.
func (r *Relay) DeliverBatch(ctx context.Context) (claimed, delivered int, err error) {
	if r.outbox == nil || r.outbox.db == nil {
		return 0, 0, ErrNoOutbox
	}
	if r.sink == nil {
		return 0, 0, errors.New("identity/auditoutbox: relay has no sink")
	}

	tx, err := r.outbox.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	// Rolled back unconditionally; after a successful Commit this is a no-op
	// returning sql.ErrTxDone. A panic or a process death between here and the
	// Commit therefore leaves every claimed intent undelivered, which is the
	// crash contract this design rests on.
	defer func() { _ = tx.Rollback() }()

	intents, err := r.outbox.claim(ctx, tx, r.cfg.batchSize())
	if err != nil {
		return 0, 0, err
	}
	if len(intents) == 0 {
		// Nothing claimed: commit (releasing the snapshot) and report an empty
		// batch rather than holding the transaction open.
		return 0, 0, tx.Commit()
	}

	log := r.cfg.logger()
	var failures int
	for _, intent := range intents {
		if derr := r.sink.Deliver(ctx, intent.Intent); derr != nil {
			failures++
			log.Error("audit outbox relay: delivery failed; intent retained for retry",
				"event_id", intent.EventID, "action", intent.Action,
				"attempts", intent.Attempts+1, "error", derr)
			if rerr := r.outbox.recordFailure(ctx, tx, intent.EventID, derr); rerr != nil {
				return len(intents), 0, rerr
			}
			continue
		}

		// Shipping is best-effort BY DESIGN and deliberately after the durable
		// write. The destination table is the audit trail; a shipper is external
		// visibility. Holding the intent for a broken SIEM would grow the
		// backlog without protecting the record, so a shipping failure is
		// counted and logged, not retried here.
		r.ship(ctx, intent.Intent)

		if merr := r.outbox.markDelivered(ctx, tx, intent.EventID); merr != nil {
			return len(intents), 0, merr
		}
		delivered++
	}

	if failures > 0 && r.cfg.Observer.DeliveryFailures != nil {
		r.cfg.Observer.DeliveryFailures(failures)
	}
	if err := tx.Commit(); err != nil {
		// Nothing was marked. Every intent in this batch is still pending and
		// will be claimed again.
		return len(intents), 0, err
	}
	return len(intents), delivered, nil
}

// ship forwards a delivered intent to the configured external shipper.
func (r *Relay) ship(ctx context.Context, intent Intent) {
	if r.shipper == nil {
		return
	}
	entry := &Entry{
		Timestamp: intent.OccurredAt,
		// The stable event id travels with the entry so a SIEM can collapse a
		// redelivery instead of counting the same grant twice.
		EventID:        intent.EventID,
		Action:         intent.Action,
		UserID:         derefString(intent.ActorUserID),
		ActorEmail:     derefString(intent.ActorEmail),
		OrganizationID: derefString(intent.OrganizationID),
		ResourceType:   derefString(intent.ResourceType),
		ResourceID:     derefString(intent.ResourceID),
		IPAddress:      derefString(intent.IPAddress),
		Metadata:       intent.Metadata,
	}

	if err := r.shipper.Ship(ctx, entry); err != nil {
		r.cfg.logger().Error("audit outbox relay: external shipping failed (the durable audit record is unaffected)",
			"event_id", intent.EventID, "error", err)
		if r.cfg.Observer.ShipFailures != nil {
			r.cfg.Observer.ShipFailures(1)
		}
	}
}

// observeBacklog publishes the undelivered depth and shouts when it grows.
//
// The backlog cannot be bounded by discarding it — that would throw away the
// records the outbox exists to keep — so it is bounded by being LOUD instead: a
// value the host can alert on, and an ERROR line naming the depth and the age of
// the oldest intent once it crosses the threshold.
func (r *Relay) observeBacklog(ctx context.Context) {
	log := r.cfg.logger()
	backlog, err := r.outbox.Backlog(ctx)
	if err != nil {
		log.Error("audit outbox relay: failed to read backlog", "error", err)
		return
	}

	if r.cfg.Observer.Backlog != nil {
		r.cfg.Observer.Backlog(backlog)
	}

	warnAt := r.cfg.backlogWarn()
	if warnAt > 0 && backlog.Pending >= warnAt {
		var oldestAge int64
		if !backlog.OldestPending.IsZero() {
			oldestAge = int64(time.Since(backlog.OldestPending).Seconds())
		}
		log.Error("audit outbox backlog is not draining: privileged mutations are recorded but have not reached the audit table",
			"outbox", r.outbox.Table(), "pending", backlog.Pending, "failed_at_least_once", backlog.Failed,
			"oldest_age_seconds", oldestAge, "threshold", warnAt)
	}
}

// prune removes delivered intents past their retention.
func (r *Relay) prune(ctx context.Context) {
	retain := r.cfg.retainDelivered()
	if retain < 0 {
		return
	}
	log := r.cfg.logger()
	pruned, err := r.outbox.PruneDelivered(ctx, time.Now().Add(-retain), r.cfg.batchSize()*defaultRelayMaxBatches)
	if err != nil {
		log.Error("audit outbox relay: prune failed", "error", err)
		return
	}
	if pruned > 0 {
		if r.cfg.Observer.Pruned != nil {
			r.cfg.Observer.Pruned(pruned)
		}
		log.Info("audit outbox relay: pruned delivered intents", "pruned", pruned, "retain", retain)
	}
}
