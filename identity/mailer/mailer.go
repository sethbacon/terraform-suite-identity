// Package mailer implements the shared outbound-SMTP transport used by every
// Terraform suite app's notification system (registry, state manager, ...).
// It is intentionally minimal: given an already-built RFC 5322 message, it
// dials the configured relay, negotiates TLS according to Config.TLSMode, and
// delivers the message. Building the message (headers, CRLF sanitization) and
// fanning an event out to channels/recipients stays app-side.
//
// This package exists because the TLS-negotiation logic is easy to get subtly
// wrong in a way that fails safe on paper but doesn't in practice: two
// independent reimplementations of "encrypted means encrypted" diverged,
// and one of them silently sent a message in plaintext when a relay didn't
// advertise STARTTLS (by delegating to net/smtp.SendMail, which upgrades
// opportunistically and falls back to plaintext with no error). Sharing one
// implementation means that class of bug can only be fixed, or reintroduced,
// once.
package mailer

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strconv"
	"sync/atomic"
	"time"
)

// TLSMode selects how Send secures the connection to the relay.
//
// The ZERO VALUE IS TLSRequired, and that is the entire point of the type.
// This field's predecessor was `UseTLS bool`, whose zero value selected
// PLAINTEXT: `mailer.Config{Host: h, Port: p, From: f}` — the minimal literal
// anyone writes from the field list without also reading the field's doc
// comment — silently sent every message in the clear, and this was the one
// Config in the module whose zero value was the LESS secure choice.
// httpsafe.Guard's zero value is strict-deny, oidc.Config's zero value
// requires an HTTPS issuer, store.AuditScope's zero value denies everything,
// and suite.NewDiscoveryClient refuses a plaintext sibling URL outright.
//
// The trap was demonstrably walkable rather than theoretical: this package's
// OWN tests reached for that exact three-field literal in four places, and
// each one got plaintext without a word in the diff saying so.
//
// Plaintext is still fully available — an unauthenticated internal relay is a
// legitimate deployment — but it can no longer be reached by OMISSION. It
// requires naming TLSDisabled, which is a word that appears in a diff and that
// a reviewer can question.
type TLSMode int

const (
	// TLSRequired, the zero value, connects with implicit TLS (SMTPS, the
	// port 465 pattern) and falls back to an explicit STARTTLS upgrade (the
	// port 587/25 submission pattern) if the TLS dial itself fails to
	// connect. The STARTTLS upgrade is issued unconditionally rather than
	// only when the relay's EHLO advertises the extension, so a relay that
	// omits (or conditionally refuses) that advertisement yields an error
	// instead of a silent plaintext send — see sendStartTLS.
	TLSRequired TLSMode = iota

	// TLSDisabled keeps the connection in plaintext and never attempts a
	// STARTTLS upgrade even when the relay advertises the extension — see
	// sendPlain for why the upgrade is not attempted opportunistically.
	//
	// This is a real, supported configuration for an unauthenticated relay on
	// a trusted network. It is NOT supported for a relay this module must
	// authenticate to: Send refuses to pair TLSDisabled with a Username on a
	// non-local relay rather than putting the password on the wire.
	TLSDisabled
)

// String renders the mode for error messages and logs.
func (m TLSMode) String() string {
	switch m {
	case TLSRequired:
		return "required"
	case TLSDisabled:
		return "disabled"
	default:
		return "invalid(" + strconv.Itoa(int(m)) + ")"
	}
}

// valid reports whether m is one of the defined modes. An undefined mode is
// refused by Send rather than falling through to a transport, so a value
// arriving from a numeric conversion (`TLSMode(n)` over some app's own config
// integer) cannot land on a transport nobody chose.
func (m TLSMode) valid() bool {
	return m == TLSRequired || m == TLSDisabled
}

// TLSModeForUseTLS maps a boolean "use TLS" flag onto the corresponding
// TLSMode: true is TLSRequired, false is TLSDisabled.
//
// It exists because both consuming apps expose SMTP TLS as a boolean in a
// contract they cannot change — a `use_tls` key in a YAML file, in a persisted
// JSON settings blob, and in a public admin API request body. Those booleans
// have to become a TLSMode somewhere, at several call sites each, and a
// hand-written conditional (or worse, a hand-written negation) at every one of
// them is exactly the edit that gets inverted in a later refactor and produces
// a silent plaintext downgrade that still compiles. This puts the polarity in
// ONE place, in the package that owns the meaning, with a test on it.
//
// Note the asymmetry with the zero value, and that it is deliberate: an
// ABSENT bool is indistinguishable from an explicit false in Go, so a caller
// whose flag came from `json.Unmarshal` into a plain `bool` should check
// whether the key was actually present (decode into a *bool) before calling
// this. Where the key is genuinely absent, do not call it — leave TLSMode at
// its zero value and get TLS.
func TLSModeForUseTLS(useTLS bool) TLSMode {
	if useTLS {
		return TLSRequired
	}
	return TLSDisabled
}

// Config is the shared outbound mail relay used to deliver a message. Host
// empty means outbound mail is disabled; callers should check that before
// calling Send.
//
// The zero Config is a DISABLED relay (empty Host), not a plaintext one; if it
// is nevertheless handed to Send, the transport it selects is TLS.
type Config struct {
	Host     string
	Port     int
	From     string
	Username string
	Password string
	// TLSMode selects the transport security level. The zero value is
	// TLSRequired — see TLSMode.
	TLSMode TLSMode
}

// defaultSendTimeout is the fallback deadline Send applies to the WHOLE SMTP
// conversation when the caller's context carries none of its own.
//
// Only the TCP dial is bounded by context cancellation; every subsequent step
// (greeting, EHLO, STARTTLS, AUTH, MAIL, RCPT, DATA, QUIT) goes through
// net/smtp, which is not context-aware, so the connection deadline set below
// is the only thing that can end them. Without a fallback, a caller holding an
// app-lifetime context — which is exactly what a background job's context is —
// would block here forever against a relay that accepts the connection and
// then stalls, wedging that job for the life of the process.
//
// The value is a whole-conversation cap, not a per-command one. RFC 5321
// §4.5.3.2 recommends per-command client timeouts on the order of minutes, so
// this is deliberately generous enough not to fail a slow-but-working relay,
// while still guaranteeing the call returns.
const defaultSendTimeout = 2 * time.Minute

// sendTimeoutOverride shortens the fallback deadline. It exists only so a test
// can watch the deadline fire without waiting the production budget, and it is
// atomic because Send reads it on whichever goroutine the caller is running
// while a finished test may be restoring it — a plain var would be a data race
// by construction. Zero (the default, and what a test restores) means
// defaultSendTimeout.
var sendTimeoutOverride atomic.Int64

// sendTimeout is the fallback deadline in force right now.
func sendTimeout() time.Duration {
	if ns := sendTimeoutOverride.Load(); ns > 0 {
		return time.Duration(ns)
	}
	return defaultSendTimeout
}

// authFor returns the SMTP authentication mechanism for the configured
// credentials, or nil when no username is set (an internal relay may accept
// unauthenticated mail, and PlainAuth.Start would otherwise refuse to send a
// password over a connection it doesn't recognize as encrypted or local).
func authFor(cfg Config) smtp.Auth {
	if cfg.Username == "" {
		return nil
	}
	return smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
}

// isLocalRelay reports whether host names the local machine.
//
// It mirrors the exemption net/smtp's PlainAuth applies when deciding whether
// it may send a password over an unencrypted connection, so this package's own
// refusal (see Send) draws the line in exactly the same place rather than in a
// place that merely looks similar.
func isLocalRelay(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// Send delivers msg (a pre-built RFC 5322 message, headers included) to the
// recipients through the configured relay. Under cfg.TLSMode's default
// (TLSRequired) an implicit TLS connection (port 465) is attempted first,
// falling back to an explicit STARTTLS upgrade (port 587/25 pattern) on dial
// failure. Under TLSDisabled the connection is deliberately kept plaintext —
// see sendPlain.
//
// Send refuses, before opening any connection, to send a PASSWORD over a
// plaintext connection to a non-local relay: TLSDisabled together with a
// non-empty Username is a configuration error, not a transport choice, and it
// is far more likely to be an oversight than the documented deliberate case
// (which is an UNAUTHENTICATED internal relay).
//
// That refusal is stated here rather than left to net/smtp. PlainAuth.Start
// applies the same rule today, so the property currently holds by borrowing —
// it lives in the auth mechanism authFor happens to return, not in this
// package. Swapping that mechanism for one without the check (LOGIN and
// CRAM-MD5 have none) would delete the protection silently, with nothing in
// this file changing. Asserting it here pins it to the transport instead, and
// converts a late, opaque "smtp auth: unencrypted connection" — surfaced only
// after a connection is open — into an early error that names the
// configuration at fault.
//
// Send always returns. When ctx carries no deadline of its own, Send imposes
// sendTimeout on the whole conversation, so a relay that accepts the TCP
// connection and then stalls produces a timeout error rather than blocking the
// caller indefinitely. A caller that wants a tighter (or looser) bound passes
// a context with its own deadline, which is honoured as-is.
func Send(ctx context.Context, cfg Config, to []string, msg []byte) error {
	// Validate before spending a context node, a timer or a socket on a
	// configuration that cannot be honoured.
	if !cfg.TLSMode.valid() {
		return fmt.Errorf("smtp: TLSMode is %s, which is not a defined mode; refusing to send rather than choosing a transport security level nobody configured", cfg.TLSMode)
	}
	if cfg.TLSMode == TLSDisabled && cfg.Username != "" && !isLocalRelay(cfg.Host) {
		return fmt.Errorf("smtp: refusing to send credentials to relay %q over a plaintext connection: TLSMode is disabled but a username is configured, which would put the SMTP password on the wire in the clear; set TLSMode to TLSRequired, or clear the username if the relay is genuinely unauthenticated", cfg.Host)
	}
	if cfg.TLSMode == TLSDisabled && cfg.Username != "" {
		// The local-relay case net/smtp also permits. It is legitimate (the
		// password never leaves the machine) but it is still a password on an
		// unencrypted socket, so it is recorded rather than passed over in
		// silence.
		slog.Warn("smtp: sending credentials over a plaintext connection to a local relay",
			"host", cfg.Host, "tls_mode", cfg.TLSMode.String())
	}

	// A background job's context is cancelled at shutdown but has no deadline,
	// so without this the entire SMTP conversation below would be unbounded.
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, sendTimeout())
		defer cancel()
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	auth := authFor(cfg)
	if cfg.TLSMode == TLSDisabled {
		return sendPlain(ctx, addr, cfg.Host, auth, cfg.From, to, msg)
	}
	return sendTLS(ctx, addr, cfg.Host, auth, cfg.From, to, msg)
}

// sendPlain connects without TLS and sends a message, deliberately never
// attempting a STARTTLS upgrade even if the relay advertises the extension.
// This is the TLSDisabled path: many relays advertise STARTTLS even when
// unauthenticated/internal, and opportunistically upgrading (as
// net/smtp.SendMail does, with no way to opt out) would fail the handshake
// against a self-signed or otherwise untrusted certificate, aborting a send
// the operator explicitly configured as plaintext.
func sendPlain(ctx context.Context, addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial smtp relay: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp handshake: %w", err)
	}
	defer func() { _ = c.Close() }()
	return finish(c, auth, from, to, msg)
}

// sendTLS connects via implicit TLS (port 465 / SMTPS) and sends a message,
// falling back to the STARTTLS pattern (port 587/25) if the TLS dial itself
// fails to connect.
func sendTLS(ctx context.Context, addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	dialer := &tls.Dialer{Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return sendStartTLS(ctx, addr, host, auth, from, to, msg)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp handshake: %w", err)
	}
	defer func() { _ = c.Close() }()
	return finish(c, auth, from, to, msg)
}

// sendStartTLS connects in plaintext, then upgrades via STARTTLS (the
// standard submission-port pattern) before authenticating and sending. It
// calls c.StartTLS directly instead of delegating to net/smtp.SendMail:
// SendMail only upgrades when the server's EHLO response advertises the
// STARTTLS extension, and otherwise silently continues in plaintext — so a
// relay that omits (or conditionally refuses) that advertisement would make a
// TLSRequired send quietly succeed unencrypted. Calling StartTLS explicitly
// guarantees the upgrade is attempted and any failure (e.g. the relay
// rejecting it) is surfaced as a real error rather than swallowed.
func sendStartTLS(ctx context.Context, addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial smtp relay: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp handshake: %w", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
		return fmt.Errorf("smtp starttls: %w", err)
	}
	return finish(c, auth, from, to, msg)
}

// finish authenticates (when auth is non-nil) and delivers msg over an
// already-connected (and, if applicable, already-encrypted) client.
//
// Reaching here over sendPlain with credentials set is only possible for a
// LOCAL relay — Send rejects every other plaintext-plus-credentials
// combination before dialling — and PlainAuth permits that case, so the
// backstop below is net/smtp's own identical rule rather than this package's.
func finish(c *smtp.Client, auth smtp.Auth, from string, to []string, msg []byte) error {
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp rcpt %q: %w", rcpt, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		// Release the DATA writer on the way out, as every other path here
		// does. Nothing is stranded without this — w wraps the client's own
		// connection, and the caller's deferred c.Close() tears that down on
		// every path — so this is symmetry rather than a repair: the function
		// closes what it opens, and a later edit that gives w an independent
		// resource does not have to remember to add it. The write error is
		// what the caller needs, so the close error is discarded.
		_ = w.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp finalize: %w", err)
	}
	return c.Quit()
}
