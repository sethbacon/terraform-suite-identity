// notifier.go implements Notifier, which fans a notification Event out to
// admin-configured delivery channels (webhook, Slack, Microsoft Teams, or an
// ad-hoc email recipient list). Channel targets are stored encrypted (via the
// shared TokenCipher) and decrypted only here at send time. Every outbound
// webhook/Slack/Teams request is routed through the shared httpsafe.Guard
// (resolve-and-pin SSRF protection), and any dial/transport error is
// stripped of the request URL before it is recorded — the channel target is
// a capability-bearing secret and must never leak through last_error.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	neturl "net/url"
	"strings"
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity/crypto"
	"github.com/sethbacon/terraform-suite-identity/identity/httpsafe"
	"github.com/sethbacon/terraform-suite-identity/identity/mailer"
)

// Event is a single alert-worthy occurrence to fan out to subscribed channels.
type Event struct {
	Type    string
	Title   string
	Message string
}

// Options carries the small pieces of copy/identity that differ between
// consuming apps; everything else about channel delivery is identical.
type Options struct {
	// Source identifies the sending app in the generic JSON webhook payload's
	// "source" field (e.g. "terraform-registry", "terraform-state-manager").
	Source string
	// TestMessage is the body used by SendTest's fixed test message (e.g.
	// "This is a test from the Terraform Registry.").
	TestMessage string
}

// SMTPProvider returns a live snapshot of the outbound SMTP relay config. It
// is invoked on every send (not cached), so an admin updating the app's own
// config struct in place (e.g. via a PUT /admin/notifications/config handler)
// is observed immediately without recreating the Notifier or requiring the
// app's config type and mailer.Config to be memory-aliased.
type SMTPProvider func() mailer.Config

// Notifier fans an Event out to the channels subscribed to it.
type Notifier struct {
	repo        *ChannelRepository
	smtp        SMTPProvider
	tokenCipher *crypto.TokenCipher
	client      *http.Client
	logger      *slog.Logger
	opts        Options
}

// NewNotifier builds a Notifier over the channel repository. smtp provides
// the live SMTP relay config used to deliver "email" channel targets and
// SendTestEmail; it is called on every send so a runtime configuration
// update (e.g. via the admin notifications API) is observed without
// recreating the Notifier. A nil smtp disables the email channel type
// (matching an empty-Host config). tokenCipher decrypts channel targets at
// send time. guard applies the deployment's egress policy to every
// webhook/Slack/Teams POST — the channel target is an admin-configured URL,
// so it MUST route through the same dial-time SSRF guard as every other
// outbound client (metadata endpoints, loopback, and RFC 1918 ranges are
// blocked unless explicitly allow-listed). A nil guard yields the strict
// default policy.
//
// A nil tokenCipher (a host constructed before its encryption key was wired
// up) disables channel delivery: every send then fails with an explicit
// "encryption key not configured" error recorded against the channel. It does
// NOT panic — this constructor already tolerates a nil smtp and a nil guard,
// so a nil pointer reaching a background goroutine's delivery path must fail
// as an error, not as a process-terminating dereference.
func NewNotifier(repo *ChannelRepository, smtp SMTPProvider, tokenCipher *crypto.TokenCipher, guard *httpsafe.Guard, opts Options) *Notifier {
	if smtp == nil {
		smtp = func() mailer.Config { return mailer.Config{} }
	}
	return &Notifier{
		repo:        repo,
		smtp:        smtp,
		tokenCipher: tokenCipher,
		client:      httpsafe.NewClient(10*time.Second, guard),
		logger:      slog.With("component", "notify"),
		opts:        opts,
	}
}

// Notify delivers ev to every enabled channel subscribed to ev.Type.
// Best-effort: a failing channel is logged and recorded but never blocks the
// others. Safe to call in a goroutine; pass a context with its own deadline.
// A nil Notifier (channels not wired up, e.g. in tests) is a no-op.
func (n *Notifier) Notify(ctx context.Context, ev Event) {
	if n == nil {
		return
	}
	// ChannelRepository's methods dereference their receiver's *sql.DB, so a
	// Notifier built with a nil repo would panic here — inside whatever
	// goroutine the caller was told was safe. Degrade to a logged no-op.
	if n.repo == nil {
		n.logger.Error("notification channels are not configured", "event", ev.Type)
		return
	}
	channels, err := n.repo.ListEnabledForEvent(ctx, ev.Type)
	if err != nil {
		n.logger.Error("failed to load notification channels", "event", ev.Type, "error", err)
		return
	}
	for i := range channels {
		_ = n.deliver(ctx, &channels[i], ev.Title, ev.Message)
	}
}

// SendTest delivers a fixed test message to one channel (the admin UI "test" button).
func (n *Notifier) SendTest(ctx context.Context, channelID string) error {
	if n == nil || n.repo == nil {
		return fmt.Errorf("notifications are not available")
	}
	// GetByID reports a missing channel as store.ErrNotFound; returning it
	// unwrapped lets a handler map it to 404 with errors.Is instead of matching
	// on the string "channel not found" this used to fabricate.
	ch, err := n.repo.GetByID(ctx, channelID)
	if err != nil {
		return err
	}
	return n.deliver(ctx, ch, "Test notification", n.opts.TestMessage)
}

// SendTestEmail delivers an ad-hoc message directly through the shared SMTP
// relay, independent of any configured channel — the "send test email"
// action for the SMTP relay settings themselves.
func (n *Notifier) SendTestEmail(ctx context.Context, recipients []string, subject, body string) error {
	if n == nil {
		return fmt.Errorf("notifications are not available")
	}
	return n.sendEmail(ctx, strings.Join(recipients, ","), subject, body)
}

func (n *Notifier) deliver(ctx context.Context, ch *NotificationChannel, title, message string) error {
	target, err := n.decryptTarget(ch)
	if err != nil {
		n.record(ctx, ch.ID, err)
		return err
	}
	// Email targets are recipient address(es) sent through the shared relay;
	// the other types POST to the decrypted destination URL.
	var sendErr error
	if ch.Type == "email" {
		sendErr = n.sendEmail(ctx, target, title, message)
	} else {
		sendErr = n.send(ctx, ch.Type, target, title, message)
	}
	if sendErr != nil {
		n.logger.Warn("notification delivery failed", "channel", ch.Name, "error", sendErr)
		n.record(ctx, ch.ID, sendErr)
		return sendErr
	}
	n.record(ctx, ch.ID, nil)
	return nil
}

func (n *Notifier) decryptTarget(ch *NotificationChannel) (string, error) {
	if ch.EncryptedTarget == "" {
		return "", fmt.Errorf("channel has no target configured")
	}
	// TokenCipher.Open has a pointer receiver and dereferences the master key
	// past its empty-ciphertext short-circuit, so calling it on a nil cipher
	// panics — and deliver reaches here for every channel type, from goroutines
	// this package documents as safe to call. Fail the delivery instead.
	if n.tokenCipher == nil {
		return "", fmt.Errorf("notifications: encryption key not configured")
	}
	// Accepts both the context-bound form (TargetContext, written by a host on
	// the current release) and the unbound legacy form, so delivery keeps
	// working for rows not yet converted (#153). A ciphertext bound to a
	// DIFFERENT channel fails here rather than falling through to the legacy
	// read — that is the binding doing its job, and it is what stops a target
	// being moved between channel rows by anyone with database write access.
	pt, _, err := n.tokenCipher.OpenWithContextOrLegacy(ch.EncryptedTarget, TargetContext(ch.ID))
	if err != nil {
		return "", fmt.Errorf("decrypt channel target: %w", err)
	}
	return pt, nil
}

func (n *Notifier) send(ctx context.Context, channelType, url, title, message string) error {
	var payload any
	switch channelType {
	case "slack":
		// Slack incoming-webhook format.
		payload = map[string]string{"text": title + "\n" + message}
	case "teams":
		// Microsoft Teams via a Power Automate "Workflows" incoming webhook, which
		// expects an Adaptive Card message envelope (the classic Office 365
		// connector MessageCard format is being retired).
		payload = teamsPayload(title, message)
	default:
		// Generic JSON webhook.
		payload = map[string]any{"title": title, "message": message, "source": n.opts.Source}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	// The URL is an admin-configured channel target (decrypted above), not user input.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		// The channel target is a capability-bearing secret (e.g. a Slack
		// incoming-webhook URL), so it is encrypted at rest and never returned
		// by the API. http.Client.Do returns a *url.Error whose message embeds
		// the full request URL; surfacing that verbatim in last_error (which
		// the admin API returns) would leak the secret. Strip the URL and keep
		// only the underlying transport error.
		return fmt.Errorf("send: %w", redactURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("destination returned status %d", resp.StatusCode)
	}
	return nil
}

// redactURLError unwraps a *url.Error so the resulting message carries only the
// underlying transport error (e.g. "dial tcp ...: connection refused" or the
// egress-policy rejection) without the request URL, which is a capability
// secret for webhook/Slack/Teams channels.
func redactURLError(err error) error {
	var urlErr *neturl.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}

// teamsPayload builds the Adaptive Card message envelope a Teams "Workflows"
// incoming webhook accepts: a single text card with a bold title over the body.
func teamsPayload(title, message string) map[string]any {
	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content": map[string]any{
				"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
				"type":    "AdaptiveCard",
				"version": "1.4",
				"body": []map[string]any{
					{"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": true},
					{"type": "TextBlock", "text": message, "wrap": true},
				},
			},
		}},
	}
}

// sendEmail delivers the alert to the recipient(s) through the shared SMTP
// relay (identity/mailer), building the RFC 5322 message here.
func (n *Notifier) sendEmail(ctx context.Context, recipients, subject, body string) error {
	to, err := ParseRecipients(recipients)
	if err != nil {
		return err
	}
	cfg := n.smtp()
	if cfg.Host == "" {
		return fmt.Errorf("smtp relay is not configured")
	}
	msg := BuildMessage(cfg.From, to, subject, body)
	return mailer.Send(ctx, cfg, to, msg)
}

// BuildMessage composes RFC 5322 headers plus a plain-text body. CR/LF is
// stripped from header-bound fields (From/To/Subject) to prevent SMTP header
// injection; each must occupy a single line. The body is not header-bound, so
// it is delivered as-is after the blank line.
//
// Exported so a caller that needs to send through a one-off SMTP config not
// tied to a Notifier (e.g. "send test email" with request-overridden,
// not-yet-saved SMTP settings) can build the same message shape and deliver
// it directly via mailer.Send, without duplicating CRLF-injection-sensitive
// header construction.
func BuildMessage(from string, to []string, subject, body string) []byte {
	recipients := make([]string, len(to))
	for i, addr := range to {
		recipients[i] = sanitizeHeader(addr)
	}
	headers := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
		sanitizeHeader(from), strings.Join(recipients, ", "), sanitizeHeader(subject),
	)
	return []byte(headers + body + "\r\n")
}

// sanitizeHeader removes CR and LF characters so a value cannot inject
// additional SMTP headers (email header / CRLF injection). Per RFC 5322 a
// header value must occupy a single line.
func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// ParseRecipients splits a comma-separated recipient list and validates each
// as an RFC 5322 address. Shared by the admin API (channel validation) and
// the email sender so both agree on what a valid target looks like.
func ParseRecipients(list string) ([]string, error) {
	parts := strings.Split(list, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		addr := strings.TrimSpace(p)
		if addr == "" {
			continue
		}
		if _, err := mail.ParseAddress(addr); err != nil {
			return nil, fmt.Errorf("invalid email address %q", addr)
		}
		out = append(out, addr)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one recipient email is required")
	}
	return out, nil
}

// record stamps the outcome of a delivery attempt. Errors are logged only —
// a failure to record delivery status must never surface as a notify failure.
func (n *Notifier) record(ctx context.Context, channelID string, sendErr error) {
	if n.repo == nil {
		return
	}
	status, msg := "sent", ""
	if sendErr != nil {
		status, msg = "failed", sendErr.Error()
	}
	if err := n.repo.RecordDelivery(ctx, channelID, status, msg, time.Now()); err != nil {
		n.logger.Error("failed to record delivery", "channel_id", channelID, "error", err)
	}
}
