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
)

// fakeSMTPServer accepts a single connection and speaks just enough SMTP to
// exercise the transport: it always advertises AUTH, optionally advertises
// STARTTLS in the EHLO response, and replies to a STARTTLS command with
// starttlsResponse verbatim (e.g. "220 go ahead" or a rejection like
// "454 4.3.3 TLS not available after start" — the exact response a live relay
// returned that this package exists to correctly surface as an error rather
// than silently continuing in plaintext).
func fakeSMTPServer(t *testing.T, advertiseSTARTTLS bool, starttlsResponse string) (host string, port int, closeFn func()) {
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
		r := bufio.NewReader(conn)
		writeLine := func(s string) { _, _ = fmt.Fprint(conn, s+"\r\n") }
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
					writeLine("250 OK: queued")
				}
				continue
			}
			switch {
			case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
				writeLine("250-fake.smtp.local")
				if advertiseSTARTTLS {
					writeLine("250-STARTTLS")
				}
				writeLine("250 AUTH PLAIN")
			case strings.HasPrefix(upper, "STARTTLS"):
				writeLine(starttlsResponse)
			case strings.HasPrefix(upper, "AUTH"):
				writeLine("235 OK")
			case strings.HasPrefix(upper, "MAIL FROM"), strings.HasPrefix(upper, "RCPT TO"):
				writeLine("250 OK")
			case upper == "DATA":
				writeLine("354 Start mail input")
				inData = true
			case upper == "QUIT":
				writeLine("221 Bye")
				return
			default:
				writeLine("500 unrecognized command")
			}
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	pn, _ := strconv.Atoi(p)
	return h, pn, func() { _ = ln.Close() }
}

// TestSend_PlainSuccess drives the plaintext transport end to end against a
// fake relay, with no auth (an unauthenticated internal relay).
func TestSend_PlainSuccess(t *testing.T) {
	host, port, closeFn := fakeSMTPServer(t, false, "")
	defer closeFn()

	cfg := Config{Host: host, Port: port, From: "notify@example.com"} // UseTLS=false, no username
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
	host, port, closeFn := fakeSMTPServer(t, true, `454 4.3.3 TLS not available after start`)
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

// TestSend_TLSDialFallbackFails exercises the UseTLS branch when both the
// implicit TLS dial and the STARTTLS fallback dial fail to connect at all
// (port bound then released, so the relay is entirely unreachable).
func TestSend_TLSDialFallbackFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(p)
	_ = ln.Close() // free the port so subsequent dials are refused immediately

	cfg := Config{Host: h, Port: port, From: "notify@example.com", UseTLS: true}
	if err := Send(context.Background(), cfg, []string{"ops@example.com"}, []byte("x")); err == nil {
		t.Fatal("expected an error dialing an unreachable TLS relay")
	}
}

// TestSend_NeverAttemptsSTARTTLSWhenUseTLSFalse is the regression test for a
// distinct bug: when UseTLS=false, the relay may still advertise STARTTLS
// (common even for internal/unauthenticated relays), but Send must never
// attempt the upgrade — unlike net/smtp.SendMail, which opportunistically
// upgrades whenever the extension is offered and would fail the handshake
// against a relay with a self-signed or otherwise untrusted certificate,
// aborting a send the operator explicitly configured as plaintext.
func TestSend_NeverAttemptsSTARTTLSWhenUseTLSFalse(t *testing.T) {
	host, port, closeFn := fakeSMTPServer(t, true, "220 go ahead")
	defer closeFn()

	cfg := Config{Host: host, Port: port, From: "notify@example.com"} // UseTLS=false
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
