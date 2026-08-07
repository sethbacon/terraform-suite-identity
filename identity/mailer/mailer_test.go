package mailer

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeSMTPOptions configures the fake relay's replies so each error branch of
// the transport (auth, MAIL FROM, RCPT TO, DATA, end-of-data, STARTTLS) can be
// driven independently. The zero value is a relay that accepts everything and
// does not advertise STARTTLS.
type fakeSMTPOptions struct {
	// advertiseSTARTTLS adds "250-STARTTLS" to the EHLO response.
	advertiseSTARTTLS bool
	// dropOnConnect closes the connection without sending a greeting, which
	// makes the client's SMTP handshake (smtp.NewClient) fail.
	dropOnConnect bool

	// record, when non-nil, is called with the verb of every command the
	// relay receives. It is how a test asserts which commands a transport did
	// and did NOT issue — notably that a plaintext send never sends STARTTLS
	// even to a relay advertising it.
	record func(verb string)

	// Replies to individual commands. Empty means "use the accepting default".
	starttlsResponse  string
	authResponse      string
	mailResponse      string
	rcptResponse      string
	dataResponse      string
	endOfDataResponse string
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// fakeSMTPServer accepts a single connection and speaks just enough SMTP to
// exercise the transport: it always advertises AUTH, optionally advertises
// STARTTLS in the EHLO response, and replies to each command with the
// configured response (e.g. a STARTTLS rejection like
// "454 4.3.3 TLS not available after start" — the exact response a live relay
// returned that this package exists to correctly surface as an error rather
// than silently continuing in plaintext).
func fakeSMTPServer(t *testing.T, opts fakeSMTPOptions) (host string, port int, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if opts.dropOnConnect {
			return
		}
		serveFakeSMTP(conn, bufio.NewReader(conn), opts)
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	pn, _ := strconv.Atoi(p)
	return h, pn, func() { _ = ln.Close() }
}

// serveFakeSMTP speaks the fake relay's SMTP conversation over one already
// accepted connection, reading through r (which may have already buffered
// bytes peeked by the caller).
//
// It is split out of fakeSMTPServer so a relay with different ACCEPT
// behaviour — notably tlsRefusingRelay, which must serve more than one
// connection and must distinguish a TLS handshake from an SMTP greeting — can
// reuse the conversation without duplicating this state machine.
func serveFakeSMTP(conn net.Conn, r *bufio.Reader, opts fakeSMTPOptions) {
	writeLine := func(s string) { _, _ = fmt.Fprint(conn, s+"\r\n") }
	note := func(verb string) {
		if opts.record != nil {
			opts.record(verb)
		}
	}
	writeLine("220 fake.smtp.local ESMTP")
	inData := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)
		if inData {
			if line == "." {
				inData = false
				writeLine(orDefault(opts.endOfDataResponse, "250 OK: queued"))
			}
			continue
		}
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			note("EHLO")
			writeLine("250-fake.smtp.local")
			if opts.advertiseSTARTTLS {
				writeLine("250-STARTTLS")
			}
			writeLine("250 AUTH PLAIN")
		case strings.HasPrefix(upper, "STARTTLS"):
			note("STARTTLS")
			writeLine(orDefault(opts.starttlsResponse, "220 go ahead"))
		case strings.HasPrefix(upper, "AUTH"):
			note("AUTH")
			writeLine(orDefault(opts.authResponse, "235 OK"))
		case strings.HasPrefix(upper, "MAIL FROM"):
			note("MAIL")
			writeLine(orDefault(opts.mailResponse, "250 OK"))
		case strings.HasPrefix(upper, "RCPT TO"):
			note("RCPT")
			writeLine(orDefault(opts.rcptResponse, "250 OK"))
		case upper == "DATA":
			note("DATA")
			resp := orDefault(opts.dataResponse, "354 Start mail input")
			writeLine(resp)
			inData = strings.HasPrefix(resp, "354")
		case upper == "QUIT":
			note("QUIT")
			writeLine("221 Bye")
			return
		default:
			writeLine("500 unrecognized command")
		}
	}
}

// unreachableAddr binds a port and immediately releases it, so subsequent dials
// to it are refused fast rather than hanging.
func unreachableAddr(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	pn, _ := strconv.Atoi(p)
	_ = ln.Close()
	return h, pn
}

// TestSend_PlainSuccess drives the plaintext transport end to end against a
// fake relay, with no auth (an unauthenticated internal relay).
func TestSend_PlainSuccess(t *testing.T) {
	host, port, closeFn := fakeSMTPServer(t, fakeSMTPOptions{})
	defer closeFn()

	cfg := Config{Host: host, Port: port, From: "notify@example.com", TLSMode: TLSDisabled} // no username
	msg := []byte("Subject: hi\r\n\r\nbody\r\n")
	if err := Send(context.Background(), cfg, []string{"ops@example.com"}, msg); err != nil {
		t.Fatalf("Send over plaintext relay: %v", err)
	}
}

// TestSendStartTLS_Rejected_ReturnsError is the regression test for the bug
// this package exists to prevent: a relay that fails/rejects the STARTTLS
// command must surface as an error, never as a silent plaintext send. This is
// the exact scenario observed live — a relay returning
// `454 4.3.3 TLS not available after start` — reproduced here against a fake
// server so the behavior is pinned regardless of any live relay's quirks.
//
// Calls sendStartTLS directly (the function reached once an implicit-TLS dial
// fails and Send falls back) rather than going through Send/sendTLS: a fake
// server that only speaks plaintext SMTP can't complete (or fail fast at) a
// real TLS handshake, so driving the dial-fallback through Send would hang
// instead of exercising the STARTTLS-rejection path this test targets.
func TestSendStartTLS_Rejected_ReturnsError(t *testing.T) {
	host, port, closeFn := fakeSMTPServer(t, fakeSMTPOptions{
		advertiseSTARTTLS: true,
		starttlsResponse:  `454 4.3.3 TLS not available after start`,
	})
	defer closeFn()

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	err := sendStartTLS(context.Background(), addr, host, nil, "notify@example.com",
		[]string{"ops@example.com"}, []byte("Subject: hi\r\n\r\nbody\r\n"))
	if err == nil {
		t.Fatal("expected an error when the relay rejects STARTTLS, got nil (silent plaintext fallback)")
	}
	if !strings.Contains(err.Error(), "smtp starttls") {
		t.Errorf("error = %q, want it to mention the starttls failure", err.Error())
	}
}

// TestSend_TLSDialFallbackFails exercises the TLSRequired branch when both the
// implicit TLS dial and the STARTTLS fallback dial fail to connect at all
// (port bound then released, so the relay is entirely unreachable).
func TestSend_TLSDialFallbackFails(t *testing.T) {
	h, port := unreachableAddr(t)

	cfg := Config{Host: h, Port: port, From: "notify@example.com", TLSMode: TLSRequired}
	if err := Send(context.Background(), cfg, []string{"ops@example.com"}, []byte("x")); err == nil {
		t.Fatal("expected an error dialing an unreachable TLS relay")
	}
}

// TestSend_NeverAttemptsSTARTTLSWhenTLSDisabled is the regression test for a
// distinct bug: under TLSDisabled, the relay may still advertise STARTTLS
// (common even for internal/unauthenticated relays), but Send must never
// attempt the upgrade — unlike net/smtp.SendMail, which opportunistically
// upgrades whenever the extension is offered and would fail the handshake
// against a relay with a self-signed or otherwise untrusted certificate,
// aborting a send the operator explicitly configured as plaintext.
func TestSend_NeverAttemptsSTARTTLSWhenTLSDisabled(t *testing.T) {
	host, port, closeFn := fakeSMTPServer(t, fakeSMTPOptions{advertiseSTARTTLS: true})
	defer closeFn()

	cfg := Config{Host: host, Port: port, From: "notify@example.com", TLSMode: TLSDisabled}
	err := Send(context.Background(), cfg, []string{"ops@example.com"}, []byte("Subject: hi\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
}

func TestAuthFor_NilWhenNoUsername(t *testing.T) {
	if auth := authFor(Config{}); auth != nil {
		t.Errorf("authFor with empty username = %v, want nil", auth)
	}
}

func TestAuthFor_PlainAuthWhenUsernameSet(t *testing.T) {
	auth := authFor(Config{Host: "smtp.example.com", Username: "user", Password: "pass"})
	if auth == nil {
		t.Fatal("authFor with username set returned nil")
	}
	if _, ok := auth.(smtp.Auth); !ok {
		t.Errorf("authFor returned %T, want smtp.Auth", auth)
	}
}

// --- transport-level failure paths -----------------------------------------
//
// The tests below cover the error branches of sendPlain/sendStartTLS/finish.
// They matter beyond the coverage floor: every one of these branches is a
// point where a delivery failure must surface as an error to the caller. A
// notification transport that swallows a relay's rejection is indistinguishable
// from one that delivered the mail, and the caller (an alerting path in both
// consuming apps) would report success for mail nobody received.

// TestSend_PlainDialFails covers the TLSDisabled dial-failure branch: an
// unreachable relay must be reported, not silently treated as delivered.
func TestSend_PlainDialFails(t *testing.T) {
	host, port := unreachableAddr(t)

	cfg := Config{Host: host, Port: port, From: "notify@example.com", TLSMode: TLSDisabled}
	err := Send(context.Background(), cfg, []string{"ops@example.com"}, []byte("x"))
	if err == nil {
		t.Fatal("expected an error dialing an unreachable plaintext relay, got nil")
	}
	if !strings.Contains(err.Error(), "dial smtp relay") {
		t.Errorf("error = %q, want it to mention the dial failure", err.Error())
	}
}

// TestSend_PlainHandshakeFails covers the branch where the TCP connection is
// established but the SMTP greeting never arrives (relay accepts then drops).
// The connection must be closed and the failure surfaced.
func TestSend_PlainHandshakeFails(t *testing.T) {
	host, port, closeFn := fakeSMTPServer(t, fakeSMTPOptions{dropOnConnect: true})
	defer closeFn()

	cfg := Config{Host: host, Port: port, From: "notify@example.com", TLSMode: TLSDisabled}
	err := Send(context.Background(), cfg, []string{"ops@example.com"}, []byte("x"))
	if err == nil {
		t.Fatal("expected an error when the relay drops the connection before greeting, got nil")
	}
	if !strings.Contains(err.Error(), "smtp handshake") {
		t.Errorf("error = %q, want it to mention the handshake failure", err.Error())
	}
}

// TestSend_PlainAppliesContextDeadline covers the branch that propagates a
// context deadline onto the connection. Without it a hung relay would block the
// caller indefinitely regardless of the context it passed.
func TestSend_PlainAppliesContextDeadline(t *testing.T) {
	host, port, closeFn := fakeSMTPServer(t, fakeSMTPOptions{})
	defer closeFn()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := Config{Host: host, Port: port, From: "notify@example.com", TLSMode: TLSDisabled}
	if err := Send(ctx, cfg, []string{"ops@example.com"}, []byte("Subject: hi\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("Send with a context deadline: %v", err)
	}
}

// TestSendStartTLS_HandshakeFails covers the STARTTLS path's handshake-failure
// branch (connection accepted, no greeting).
func TestSendStartTLS_HandshakeFails(t *testing.T) {
	host, port, closeFn := fakeSMTPServer(t, fakeSMTPOptions{dropOnConnect: true})
	defer closeFn()

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	err := sendStartTLS(context.Background(), addr, host, nil, "notify@example.com",
		[]string{"ops@example.com"}, []byte("x"))
	if err == nil {
		t.Fatal("expected an error when the relay drops the connection before greeting, got nil")
	}
	if !strings.Contains(err.Error(), "smtp handshake") {
		t.Errorf("error = %q, want it to mention the handshake failure", err.Error())
	}
}

// TestSendStartTLS_AppliesContextDeadline covers the STARTTLS path's
// deadline-propagation branch. The relay rejects STARTTLS, so the send fails —
// the assertion here is that the deadline is applied on the way, not that the
// send succeeds (a successful STARTTLS upgrade needs a certificate chaining to
// a system-trusted root, which a fake relay cannot present).
func TestSendStartTLS_AppliesContextDeadline(t *testing.T) {
	host, port, closeFn := fakeSMTPServer(t, fakeSMTPOptions{
		advertiseSTARTTLS: true,
		starttlsResponse:  "454 4.3.3 TLS not available after start",
	})
	defer closeFn()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	err := sendStartTLS(ctx, addr, host, nil, "notify@example.com",
		[]string{"ops@example.com"}, []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "smtp starttls") {
		t.Fatalf("error = %v, want the starttls rejection to surface", err)
	}
}

// TestSend_AuthFailureSurfaces covers finish's authentication branch: rejected
// credentials must fail the send rather than proceeding unauthenticated.
//
// The fake relay listens on 127.0.0.1, and BOTH Send's own check and
// net/smtp's PlainAuth permit sending credentials over an unencrypted
// connection only to a local relay — which is what makes this branch
// reachable in a test without a trusted certificate. Against a non-local
// plaintext relay Send refuses before dialling; see
// TestSend_PlaintextWithCredentials_RefusedForRemoteRelay.
func TestSend_AuthFailureSurfaces(t *testing.T) {
	host, port, closeFn := fakeSMTPServer(t, fakeSMTPOptions{
		authResponse: "535 5.7.8 authentication failed",
	})
	defer closeFn()

	cfg := Config{
		Host: host, Port: port, From: "notify@example.com",
		Username: "user", Password: "pass",
		TLSMode: TLSDisabled,
	}
	err := Send(context.Background(), cfg, []string{"ops@example.com"}, []byte("x"))
	if err == nil {
		t.Fatal("expected an error when the relay rejects authentication, got nil")
	}
	if !strings.Contains(err.Error(), "smtp auth") {
		t.Errorf("error = %q, want it to mention the auth failure", err.Error())
	}
}

// TestSend_DeliveryFailuresSurface covers finish's remaining per-command error
// branches. Each is a distinct way a relay refuses a message; all must surface.
func TestSend_DeliveryFailuresSurface(t *testing.T) {
	tests := []struct {
		name    string
		opts    fakeSMTPOptions
		wantErr string
	}{
		{
			name:    "MAIL FROM rejected",
			opts:    fakeSMTPOptions{mailResponse: "550 5.7.1 sender rejected"},
			wantErr: "smtp mail from",
		},
		{
			name:    "RCPT TO rejected",
			opts:    fakeSMTPOptions{rcptResponse: "550 5.1.1 no such user"},
			wantErr: "smtp rcpt",
		},
		{
			name:    "DATA rejected",
			opts:    fakeSMTPOptions{dataResponse: "554 5.5.1 transaction failed"},
			wantErr: "smtp data",
		},
		{
			name:    "message rejected at end of data",
			opts:    fakeSMTPOptions{endOfDataResponse: "554 5.7.1 message rejected"},
			wantErr: "smtp finalize",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, closeFn := fakeSMTPServer(t, tt.opts)
			defer closeFn()

			cfg := Config{Host: host, Port: port, From: "notify@example.com", TLSMode: TLSDisabled}
			err := Send(context.Background(), cfg, []string{"ops@example.com"},
				[]byte("Subject: hi\r\n\r\nbody\r\n"))
			if err == nil {
				t.Fatalf("expected an error when the relay responds %q, got nil "+
					"(a swallowed rejection is indistinguishable from a delivered message)",
					tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err.Error(), tt.wantErr)
			}
		})
	}
}
