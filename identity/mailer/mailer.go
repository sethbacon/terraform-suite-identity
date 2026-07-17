// Package mailer implements the shared outbound-SMTP transport used by every
// Terraform suite app's notification system (registry, state manager, ...).
// It is intentionally minimal: given an already-built RFC 5322 message, it
// dials the configured relay, negotiates TLS according to Config.UseTLS, and
// delivers the message. Building the message (headers, CRLF sanitization) and
// fanning an event out to channels/recipients stays app-side.
//
// This package exists because the TLS-negotiation logic is easy to get subtly
// wrong in a way that fails safe on paper but doesn't in practice: two
// independent reimplementations of "UseTLS=true means encrypted" diverged,
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
	"net"
	"net/smtp"
	"strconv"
)

// Config is the shared outbound mail relay used to deliver a message. Host
// empty means outbound mail is disabled; callers should check that before
// calling Send.
type Config struct {
	Host     string
	Port     int
	From     string
	Username string
	Password string
	// UseTLS enables implicit TLS (port 465, falling back to STARTTLS on dial
	// failure) when true. When false, the connection is deliberately kept
	// plaintext and never opportunistically upgraded to STARTTLS even if the
	// relay advertises it — see sendPlain.
	UseTLS bool
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

// Send delivers msg (a pre-built RFC 5322 message, headers included) to the
// recipients through the configured relay. When cfg.UseTLS is set, an
// implicit TLS connection (port 465) is attempted first, falling back to an
// explicit STARTTLS upgrade (port 587/25 pattern) on dial failure; otherwise
// the connection is deliberately kept plaintext — see sendPlain.
func Send(ctx context.Context, cfg Config, to []string, msg []byte) error {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	auth := authFor(cfg)
	if cfg.UseTLS {
		return sendTLS(ctx, addr, cfg.Host, auth, cfg.From, to, msg)
	}
	return sendPlain(ctx, addr, cfg.Host, auth, cfg.From, to, msg)
}

// sendPlain connects without TLS and sends a message, deliberately never
// attempting a STARTTLS upgrade even if the relay advertises the extension.
// This is the UseTLS=false path: many relays advertise STARTTLS even when
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
// UseTLS=true send quietly succeed unencrypted. Calling StartTLS explicitly
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
// already-connected (and, if applicable, already-encrypted) client. PlainAuth
// refuses to send the password over an unencrypted connection, so auth fails
// closed if the caller reached here over sendPlain with credentials set.
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
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp finalize: %w", err)
	}
	return c.Quit()
}
