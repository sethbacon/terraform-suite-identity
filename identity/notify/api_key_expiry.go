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
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity/mailer"
	identitymodels "github.com/sethbacon/terraform-suite-identity/identity/models"
)

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
func (n *APIKeyExpiryNotifier) Start(ctx context.Context) error {
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
	n.runCheck(ctx)

	for {
		select {
		case <-ticker.C:
			n.runCheck(ctx)
		case <-n.stopChan:
			log.Println("API key expiry notifier stopped")
			return nil
		case <-ctx.Done():
			log.Println("API key expiry notifier context cancelled")
			return nil
		}
	}
}

// Stop signals the background loop to exit.
func (n *APIKeyExpiryNotifier) Stop() error {
	close(n.stopChan)
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

	warningDays := cfg.WarningDays
	if warningDays <= 0 {
		warningDays = 7
	}

	keys, err := n.apiKeyRepo.FindExpiringKeys(ctx, warningDays)
	if err != nil {
		log.Printf("API key expiry notifier: failed to query expiring keys: %v", err)
		return
	}

	if len(keys) == 0 {
		return
	}

	log.Printf("API key expiry notifier: found %d key(s) approaching expiry", len(keys))

	for _, key := range keys {
		if key.UserID == nil {
			continue
		}

		user, err := n.userRepo.GetUserByID(ctx, *key.UserID)
		if err != nil {
			log.Printf("API key expiry notifier: could not retrieve user %s for key %s: %v",
				*key.UserID, key.ID, err)
			continue
		}
		if user.Email == "" {
			continue
		}

		// Claim the notification BEFORE sending so concurrent replicas can't both
		// email this key: the conditional UPDATE is atomic, so exactly one replica
		// wins the claim and the others skip. A send failure after a won claim is a
		// missed notice (logged below), which is preferred over duplicate emails.
		claimed, err := n.apiKeyRepo.ClaimExpiryNotification(ctx, key.ID)
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
