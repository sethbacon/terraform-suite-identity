// api_key_expiry.go implements the APIKeyExpiryNotifier background job, which
// periodically scans for API keys approaching their expiry date and sends a
// warning email to the owning user. Notification state is persisted in the
// database (expiry_notification_sent_at column, identity.api_keys) so emails
// are sent exactly once even across server restarts. The job is a no-op when
// notifications are disabled or the SMTP host is not configured, so it is
// always safe to start regardless of deployment environment.
//
// This is a personal notice to the affected key owner, not an admin-facing
// broadcast, so unlike Notifier.Notify it is never routed through
// notification channels — only through the shared SMTP relay directly.
package notify

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity/internal/safeloop"
	"github.com/sethbacon/terraform-suite-identity/identity/mailer"
	identitymodels "github.com/sethbacon/terraform-suite-identity/identity/models"
	"github.com/sethbacon/terraform-suite-identity/identity/store"
)

// defaultDBTimeout bounds each individual database round-trip made from inside
// the notifier's loop.
//
// Start's context is an app-lifetime, cancel-at-shutdown context with no
// deadline, and runCheck runs synchronously inside the ticker loop. A query
// that never returns — a stalled connection, a lock wait with no server-side
// timeout — would therefore not merely fail one check: it would hang the loop
// for the life of the process, so no further expiry notification is ever sent
// to anyone. Every query this job issues is a single-row or single-index
// lookup, so a bound this generous cannot fail a healthy database, and any
// finite bound converts a permanent wedge into one logged, retried tick.
const defaultDBTimeout = 30 * time.Second

// dbTimeoutOverride shortens that bound. It exists only so a test can watch it
// fire without waiting the production budget, and it is atomic because runCheck
// reads it on the job's goroutine while a finished test may be restoring it — a
// plain var would be a data race by construction. Zero (the default, and what a
// test restores) means defaultDBTimeout.
var dbTimeoutOverride atomic.Int64

// dbTimeout is the per-query bound in force right now.
func dbTimeout() time.Duration {
	if ns := dbTimeoutOverride.Load(); ns > 0 {
		return time.Duration(ns)
	}
	return defaultDBTimeout
}

// apiKeyRepo/userRepo are the minimal slices of identity/store's
// APIKeyRepository / UserRepository this job depends on, so tests can stub
// them without a live database.
type apiKeyRepo interface {
	FindExpiringKeys(ctx context.Context, warningDays int) ([]*identitymodels.APIKey, error)
	ClaimExpiryNotification(ctx context.Context, keyID string) (bool, error)
}

type userRepo interface {
	GetUserByID(ctx context.Context, userID string) (*identitymodels.User, error)
}

// ExpiryConfig is a point-in-time snapshot of the settings that gate the
// API-key-expiry job.
type ExpiryConfig struct {
	Enabled            bool
	APIKeyExpiring     bool // notifications.events.api_key_expiring
	SMTP               mailer.Config
	WarningDays        int
	CheckIntervalHours int
}

// ExpiryConfigProvider returns a live snapshot of ExpiryConfig. It is
// re-invoked on every tick (not just once at Start) so an admin toggling
// notifications.events.api_key_expiring off via the admin API takes effect
// on the next tick without a process restart. CheckIntervalHours is read
// once, at construction, to size the ticker.
type ExpiryConfigProvider func() ExpiryConfig

// ExpiryOptions carries the small pieces of copy that differ between
// consuming apps.
type ExpiryOptions struct {
	// ProductName appears in the warning email body and sign-off (e.g.
	// "Terraform Registry", "Terraform State Manager").
	ProductName string
}

// APIKeyExpiryNotifier periodically emails users whose API keys are about to expire.
type APIKeyExpiryNotifier struct {
	apiKeyRepo apiKeyRepo
	userRepo   userRepo
	cfg        ExpiryConfigProvider
	opts       ExpiryOptions
	interval   time.Duration
	stopChan   chan struct{}
	// stopOnce makes Stop idempotent: closing an already-closed channel
	// panics, and a graceful shutdown racing a signal handler (or a retry in
	// an error path) is a realistic way to reach a second Stop.
	stopOnce sync.Once
}

// NewAPIKeyExpiryNotifier creates a new APIKeyExpiryNotifier. cfg's
// CheckIntervalHours is read once at construction to size the check
// interval (default 24h); every other field is re-read from cfg on each tick.
func NewAPIKeyExpiryNotifier(apiKeyRepo apiKeyRepo, userRepo userRepo, cfg ExpiryConfigProvider, opts ExpiryOptions) *APIKeyExpiryNotifier {
	hours := cfg().CheckIntervalHours
	if hours <= 0 {
		hours = 24
	}
	return &APIKeyExpiryNotifier{
		apiKeyRepo: apiKeyRepo,
		userRepo:   userRepo,
		cfg:        cfg,
		opts:       opts,
		interval:   time.Duration(hours) * time.Hour,
		stopChan:   make(chan struct{}),
	}
}

// Name identifies the job in a jobs.Registry.
func (n *APIKeyExpiryNotifier) Name() string { return "api-key-expiry-notifier" }

// Start runs the expiry-notification loop until ctx is cancelled or Stop is
// called. It blocks (a jobs.Registry runs it in its own goroutine); the error
// return is always nil — this job has no fatal startup error.
//
// Calling Start on a notifier that has already been stopped is a no-op: it
// logs and returns without scanning. Start is not re-entrant — one notifier
// runs one loop.
//
// A panic inside a single check is recovered and logged, and the loop
// continues with the next tick (see runTick). The goroutine this runs in
// belongs to the host application, so an unrecovered panic here would
// terminate the host process rather than fail a library call.
func (n *APIKeyExpiryNotifier) Start(ctx context.Context) error {
	// Stop can legitimately land before Start — a shutdown signal racing a
	// slow startup. Without this, a stopped notifier would still run one
	// immediate check before the select noticed the closed channel.
	if n.isStopped() {
		log.Println("API key expiry notifier: not started (already stopped)")
		return nil
	}

	cfg := n.cfg()
	if !cfg.Enabled {
		log.Println("API key expiry notifier: disabled (notifications.enabled=false)")
		return nil
	}
	if cfg.SMTP.Host == "" {
		log.Println("API key expiry notifier: disabled (notifications.smtp.host not set)")
		return nil
	}
	if !cfg.APIKeyExpiring {
		log.Println("API key expiry notifier: disabled (notifications.events.api_key_expiring=false)")
		return nil
	}

	ticker := time.NewTicker(n.interval)
	defer ticker.Stop()

	log.Printf("API key expiry notifier started (check interval: %v, warning window: %d days)",
		n.interval, cfg.WarningDays)

	// Run once immediately on startup
	n.runTick(ctx)

	for {
		select {
		case <-ticker.C:
			n.runTick(ctx)
		case <-n.stopChan:
			log.Println("API key expiry notifier stopped")
			return nil
		case <-ctx.Done():
			log.Println("API key expiry notifier context cancelled")
			return nil
		}
	}
}

// runTick runs one check behind the module's panic boundary. This is the
// repeating body of a loop the module owns and the host runs in its own
// goroutine, so it is exactly where a fault must degrade one tick instead of
// killing the process. The recovery is loud (safeloop.Guard logs the value and
// the stack at error level) — a silently swallowed panic would leave the job
// looking healthy while it quietly did nothing.
func (n *APIKeyExpiryNotifier) runTick(ctx context.Context) {
	safeloop.Guard(n.Name(), func() { n.runCheck(ctx) })
}

// isStopped reports whether Stop has already been called.
func (n *APIKeyExpiryNotifier) isStopped() bool {
	select {
	case <-n.stopChan:
		return true
	default:
		return false
	}
}

// Stop signals the background loop to exit. It is safe to call more than once
// and from several goroutines concurrently: closing an already-closed channel
// panics, and an explicit registry shutdown racing a signal handler is a
// realistic way to reach a second call. The error return is always nil.
func (n *APIKeyExpiryNotifier) Stop() error {
	n.stopOnce.Do(func() { close(n.stopChan) })
	return nil
}

// runCheck queries for expiring keys and sends notification emails.
func (n *APIKeyExpiryNotifier) runCheck(ctx context.Context) {
	// Re-checked on every run (not just at Start) so an admin toggling
	// notifications.events.api_key_expiring off via the admin API takes
	// effect on the next tick without a process restart.
	cfg := n.cfg()
	if !cfg.Enabled || cfg.SMTP.Host == "" || !cfg.APIKeyExpiring {
		return
	}
	if n.apiKeyRepo == nil {
		log.Println("API key expiry notifier: no API key repository configured; skipping check")
		return
	}

	warningDays := cfg.WarningDays
	if warningDays <= 0 {
		warningDays = 7
	}

	// Each timed call below is wrapped so its cancel func runs on a defer, not
	// only on the straight-line path. The repositories are interfaces the host
	// supplies, and runCheck runs behind safeloop.Guard's panic boundary
	// (runTick), so a panic inside one of these calls is recovered and the
	// loop keeps ticking — but a bare post-call cancel() would be skipped on
	// the way past, leaving the timer and the context node attached to the
	// parent (process-lifetime) context, one per faulting tick. The closures
	// keep the cancels attached to the calls they bound, and keep them out of
	// the loop body's defer stack.
	keys, err := func() ([]*identitymodels.APIKey, error) {
		findCtx, cancel := context.WithTimeout(ctx, dbTimeout())
		defer cancel()
		return n.apiKeyRepo.FindExpiringKeys(findCtx, warningDays)
	}()
	if err != nil {
		log.Printf("API key expiry notifier: failed to query expiring keys: %v", err)
		return
	}

	if len(keys) == 0 {
		return
	}

	log.Printf("API key expiry notifier: found %d key(s) approaching expiry", len(keys))

	for _, key := range keys {
		// apiKeyRepo is an interface, so the rows come from whatever
		// implementation the host wired in. The shipped one never yields a nil
		// element or a nil ExpiresAt (its WHERE clause requires
		// expires_at IS NOT NULL), but a dereference in this loop body is a
		// host-process crash, not a failed call, so it is guarded rather than
		// assumed.
		if key == nil || key.UserID == nil || key.ExpiresAt == nil {
			continue
		}
		if n.userRepo == nil {
			log.Println("API key expiry notifier: no user repository configured; cannot resolve key owners")
			return
		}

		user, err := func() (*identitymodels.User, error) {
			lookupCtx, cancel := context.WithTimeout(ctx, dbTimeout())
			defer cancel()
			return n.userRepo.GetUserByID(lookupCtx, *key.UserID)
		}()
		// GetUserByID reports "no such row" as store.ErrNotFound. api_keys.user_id
		// is ON DELETE SET NULL, so deleting a user whose key is inside the
		// warning window between the scan above and this lookup lands here — a
		// routine administrative action, logged as such and skipped, kept
		// distinct from a database failure so an operator reading the log can
		// tell an expected gap from a broken lookup.
		if errors.Is(err, store.ErrNotFound) {
			log.Printf("API key expiry notifier: user %s for key %s no longer exists; skipping",
				*key.UserID, key.ID)
			continue
		}
		if err != nil {
			log.Printf("API key expiry notifier: could not retrieve user %s for key %s: %v",
				*key.UserID, key.ID, err)
			continue
		}
		if user == nil {
			// The repository is an interface; a host-supplied implementation that
			// still uses the pre-v0.24.0 (nil, nil) convention would otherwise
			// crash the host process on the dereference below.
			log.Printf("API key expiry notifier: user repository returned no user and no error for %s; skipping",
				*key.UserID)
			continue
		}
		if user.Email == "" {
			continue
		}

		// Claim the notification BEFORE sending so concurrent replicas can't both
		// email this key: the conditional UPDATE is atomic, so exactly one replica
		// wins the claim and the others skip. A send failure after a won claim is a
		// missed notice (logged below), which is preferred over duplicate emails.
		claimed, err := func() (bool, error) {
			claimCtx, cancel := context.WithTimeout(ctx, dbTimeout())
			defer cancel()
			return n.apiKeyRepo.ClaimExpiryNotification(claimCtx, key.ID)
		}()
		if err != nil {
			log.Printf("API key expiry notifier: failed to claim notification for key %s: %v", key.ID, err)
			continue
		}
		if !claimed {
			// Another replica (or an earlier run) already claimed this key.
			continue
		}

		if err := n.sendExpiryEmail(ctx, cfg.SMTP, user.Email, user.Name, key.Name, key.KeyPrefix, *key.ExpiresAt); err != nil {
			log.Printf("API key expiry notifier: send failed after claiming key %s; it will NOT be retried (missed, not duplicated): %v", key.ID, err)
			continue
		}
	}
}

// sendExpiryEmail composes and delivers a plain-text warning email via SMTP.
func (n *APIKeyExpiryNotifier) sendExpiryEmail(ctx context.Context, smtp mailer.Config, toEmail, userName, keyName, keyPrefix string, expiresAt time.Time) error {
	daysLeft := int(time.Until(expiresAt).Hours()/24) + 1
	if daysLeft < 0 {
		daysLeft = 0
	}

	product := n.opts.ProductName
	subject := fmt.Sprintf("Action Required: API key '%s' expires in %d day(s)", keyName, daysLeft)
	body := strings.Join([]string{
		fmt.Sprintf("Hello %s,", userName),
		"",
		fmt.Sprintf("Your %s API key '%s' (%s...) will expire on %s (%d day(s) from now).",
			product, keyName, keyPrefix, expiresAt.UTC().Format(time.RFC1123), daysLeft),
		"",
		"To avoid service disruption, please create a replacement key before the expiry date:",
		fmt.Sprintf("  1. Log in to the %s admin UI.", product),
		"  2. Navigate to Admin \u2192 API Keys.",
		"  3. Create a new key with the same scopes and update your CI/CD pipelines.",
		"  4. Delete or let the old key expire.",
		"",
		"If you no longer need this key, no action is required.",
		"",
		fmt.Sprintf("\u2014 %s", product),
	}, "\r\n")

	msg := BuildMessage(smtp.From, []string{toEmail}, subject, body)
	return mailer.Send(ctx, smtp, []string{toEmail}, msg)
}
