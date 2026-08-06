// tlsmode_test.go pins the DIRECTION a Config that says nothing about
// transport security resolves in, and pins that saying something unsafe
// deliberately still works.
//
// Both halves are load-bearing and neither is sufficient alone. A table that
// only proved "the zero value encrypts" would pass just as happily against a
// build where the plaintext transport had been deleted or broken outright,
// which is its own outage and would be discovered by an operator with a
// legitimate unauthenticated internal relay rather than by CI. So every case
// below states which transport it expects AND why that is the right one for
// the configuration it describes.
//
// The bug being guarded is a bug of OMISSION, which is why the first row
// constructs its Config the way someone reads the struct's field list and
// writes a literal — Host, Port, From, nothing else — rather than the way
// someone who has already read the docs would.
package mailer

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// tlsRefusingRelay starts a fake relay that serves plaintext SMTP but REFUSES
// a TLS handshake by closing the connection as soon as it sees one.
//
// This is what makes Send's TLSRequired branch observable end to end. sendTLS
// dials implicit TLS first and only falls back to the STARTTLS pattern when
// that dial FAILS; against an ordinary plaintext fake relay the dial neither
// succeeds nor fails, it hangs — the fake server has no ServerHello to send
// and simply waits — so the whole call burns the fallback budget and the
// STARTTLS path is never reached. (That hang is why the pre-existing
// TestSendStartTLS_Rejected_ReturnsError calls sendStartTLS directly rather
// than going through Send.) Closing on the ClientHello turns the hang into an
// immediate dial error, so the fallback happens at once and what gets asserted
// is the behaviour of the whole Send path rather than of one unexported helper.
//
// It also accepts connections in a LOOP, because a TLSRequired send makes two
// of them: the refused TLS dial, then the plaintext one.
//
// commands returns every command verb the relay has seen. Under TLSDisabled
// that set must not contain STARTTLS even though the relay advertises it,
// which is the actual security property — an error string alone cannot tell
// "never attempted the upgrade" apart from "attempted it and it failed".
// tlsProbeWindow is how long tlsRefusingRelay waits for a client to reveal
// itself as a TLS dialer before treating the connection as plaintext SMTP.
const tlsProbeWindow = 300 * time.Millisecond

func tlsRefusingRelay(t *testing.T, opts fakeSMTPOptions) (host string, port int, commands func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var mu sync.Mutex
	var seen []string
	opts.record = func(verb string) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, verb)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				// Classify the connection by WHO SPEAKS FIRST. A TLS client
				// sends its ClientHello immediately, and a TLS record always
				// opens with the handshake content type (0x16). An SMTP client
				// says nothing until it has read our 220 greeting — so a
				// blocking read would deadlock against it, and the probe has to
				// be bounded by a deadline rather than by data.
				//
				// The window is ~1000x the round trip on loopback, and nothing
				// downstream depends on the exact value: a probe that expired
				// early would misclassify a TLS dial as SMTP, which shows up as
				// a failing assertion here, never as a false pass.
				_ = c.SetReadDeadline(time.Now().Add(tlsProbeWindow))
				probe := make([]byte, 1)
				n, _ := c.Read(probe)
				_ = c.SetReadDeadline(time.Time{})
				if n > 0 && probe[0] == 0x16 {
					return // refuse the handshake, fast
				}
				// Hand back whatever the probe consumed. A fresh bufio.Reader
				// over the raw conn would drop it, and reusing one whose Peek
				// had just timed out would replay that timeout as a sticky
				// error on the first real read.
				r := bufio.NewReader(io.MultiReader(bytes.NewReader(probe[:n]), c))
				serveFakeSMTP(c, r, opts)
			}(conn)
		}
	}()

	t.Cleanup(func() { _ = ln.Close() })

	h, ps, _ := net.SplitHostPort(ln.Addr().String())
	pn, _ := strconv.Atoi(ps)
	return h, pn, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func sawCommand(cmds []string, verb string) bool {
	for _, c := range cmds {
		if c == verb {
			return true
		}
	}
	return false
}

// TestTLSMode_ZeroValueEncrypts_ExplicitPlaintextStillWorks is the core
// bidirectional table for issue #145.
//
// The relay advertises STARTTLS and then rejects it, so the two transports are
// distinguishable twice over: by whether the send SUCCEEDS, and by whether the
// relay ever SAW a STARTTLS command. Both are asserted, because either alone
// can be satisfied for the wrong reason.
func TestTLSMode_ZeroValueEncrypts_ExplicitPlaintextStillWorks(t *testing.T) {
	tests := []struct {
		name string
		// cfg receives the relay's address and returns the Config under test,
		// so each row controls exactly how much it says about TLS.
		cfg func(host string, port int) Config
		// wantErrContains empty means the send must SUCCEED.
		wantErrContains string
		// wantSTARTTLS is whether the relay must have seen a STARTTLS command.
		wantSTARTTLS bool
		why          string
	}{
		{
			name: "zero value: the minimal literal anyone writes from the field list",
			cfg: func(host string, port int) Config {
				// Deliberately says NOTHING about transport security. Before
				// v0.25.0 this exact literal selected plaintext.
				return Config{Host: host, Port: port, From: "notify@example.com"}
			},
			wantErrContains: "smtp starttls",
			wantSTARTTLS:    true,
			why: "a Config that never mentions TLS must still insist on encryption; delivering " +
				"here would mean the zero value had silently opted out",
		},
		{
			name: "TLSRequired named explicitly: identical to the zero value",
			cfg: func(host string, port int) Config {
				return Config{Host: host, Port: port, From: "notify@example.com", TLSMode: TLSRequired}
			},
			wantErrContains: "smtp starttls",
			wantSTARTTLS:    true,
			why: "naming the default must not change it — otherwise the zero value and the " +
				"constant it claims to equal are two different behaviours",
		},
		{
			name: "TLSDisabled named explicitly: the deliberate choice is honoured",
			cfg: func(host string, port int) Config {
				return Config{Host: host, Port: port, From: "notify@example.com", TLSMode: TLSDisabled}
			},
			wantErrContains: "",
			wantSTARTTLS:    false,
			why: "an unauthenticated relay on a trusted network is a supported deployment, and the " +
				"upgrade must not be attempted opportunistically; if this row goes red the safe " +
				"default was achieved by breaking the other branch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A short fallback budget: every row resolves through a refused
			// dial or a completed conversation, so a row that reaches the
			// budget has stalled and should fail rather than hold the suite
			// for the production two minutes.
			shortSendTimeout(t, 20*time.Second)

			host, port, commands := tlsRefusingRelay(t, fakeSMTPOptions{
				advertiseSTARTTLS: true,
				starttlsResponse:  "454 4.3.3 TLS not available after start",
			})

			err := Send(context.Background(), tt.cfg(host, port),
				[]string{"ops@example.com"}, []byte("Subject: hi\r\n\r\nbody\r\n"))

			if tt.wantErrContains == "" {
				if err != nil {
					t.Fatalf("Send = %v, want success (%s)", err, tt.why)
				}
			} else {
				if err == nil {
					t.Fatalf("Send succeeded against a relay that refuses STARTTLS, want an error mentioning %q (%s)",
						tt.wantErrContains, tt.why)
				}
				if !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Fatalf("Send = %q, want it to mention %q (%s)", err.Error(), tt.wantErrContains, tt.why)
				}
			}

			cmds := commands()
			if got := sawCommand(cmds, "STARTTLS"); got != tt.wantSTARTTLS {
				t.Fatalf("relay saw STARTTLS = %v, want %v (commands: %v) — %s",
					got, tt.wantSTARTTLS, cmds, tt.why)
			}
		})
	}
}

// TestTLSModeForUseTLS_Polarity pins the bool-to-mode mapping in both
// directions.
//
// This helper exists precisely so the polarity is written down once instead of
// at every consumer call site that has a `use_tls` boolean to convert, so an
// inversion here would be an inversion everywhere at once — which is exactly
// why it is worth a test of its own rather than being covered incidentally.
func TestTLSModeForUseTLS_Polarity(t *testing.T) {
	if got := TLSModeForUseTLS(true); got != TLSRequired {
		t.Errorf("TLSModeForUseTLS(true) = %v, want TLSRequired", got)
	}
	if got := TLSModeForUseTLS(false); got != TLSDisabled {
		t.Errorf("TLSModeForUseTLS(false) = %v, want TLSDisabled", got)
	}
}

// TestTLSMode_ZeroValueIsTLSRequired pins the identity the whole fix rests on,
// independently of any transport behaviour.
//
// Asserting it directly matters because every behavioural test above reaches
// this fact through a network conversation; if the constant block were
// reordered so TLSDisabled took the iota zero slot, this fails with a message
// naming the cause instead of the symptom.
func TestTLSMode_ZeroValueIsTLSRequired(t *testing.T) {
	var zero TLSMode
	if zero != TLSRequired {
		t.Fatalf("the zero TLSMode is %v, want TLSRequired — a Config built without naming a mode must encrypt", zero)
	}
	if (Config{}).TLSMode != TLSRequired {
		t.Fatal("the zero Config's TLSMode is not TLSRequired")
	}
}

// TestSend_UndefinedTLSModeIsRefused covers the branch where a mode arrives
// from a numeric conversion rather than from one of the named constants.
//
// A host mapping its own integer setting onto TLSMode can produce a value that
// is neither constant. Falling through to a transport would mean picking a
// security level nobody configured, so Send refuses instead — and refuses
// BEFORE dialling, which is what the unreachable address here proves: a dial
// would have produced a "dial smtp relay" error instead.
func TestSend_UndefinedTLSModeIsRefused(t *testing.T) {
	host, port := unreachableAddr(t)

	cfg := Config{Host: host, Port: port, From: "notify@example.com", TLSMode: TLSMode(42)}
	err := Send(context.Background(), cfg, []string{"ops@example.com"}, []byte("x"))
	if err == nil {
		t.Fatal("Send accepted an undefined TLSMode")
	}
	if !strings.Contains(err.Error(), "not a defined mode") {
		t.Fatalf("Send = %q, want it to name the undefined mode as the cause", err.Error())
	}
	if strings.Contains(err.Error(), "dial smtp relay") {
		t.Fatalf("Send dialled before validating the mode: %q", err.Error())
	}
}

// TestTLSMode_String covers the rendering used in the error messages above, so
// a mode that reaches a log line is identifiable.
func TestTLSMode_String(t *testing.T) {
	for _, tc := range []struct {
		mode TLSMode
		want string
	}{
		{TLSRequired, "required"},
		{TLSDisabled, "disabled"},
		{TLSMode(42), "invalid(42)"},
	} {
		if got := tc.mode.String(); got != tc.want {
			t.Errorf("TLSMode(%d).String() = %q, want %q", int(tc.mode), got, tc.want)
		}
	}
}

// --- credentials over plaintext --------------------------------------------

// TestSend_PlaintextWithCredentials_RefusedForRemoteRelay pins that a password
// is never put on an unencrypted wire to a remote relay.
//
// net/smtp's PlainAuth applies the same rule, so this could be argued to be
// redundant — it is not. That check lives inside the auth MECHANISM authFor
// happens to return, not in this package: swapping PlainAuth for LOGIN or
// CRAM-MD5 (neither of which has the check) would delete the protection with
// nothing in mailer.go changing, and no test failing. This assertion is what
// makes that swap fail.
//
// The relay address is unreachable on purpose. The refusal must happen before
// any connection attempt, so a "dial smtp relay" error here would mean the
// password had already been committed to a socket's worth of intent.
func TestSend_PlaintextWithCredentials_RefusedForRemoteRelay(t *testing.T) {
	cfg := Config{
		Host: "smtp.relay.example.com", Port: 25, From: "notify@example.com",
		Username: "user", Password: "hunter2",
		TLSMode: TLSDisabled,
	}
	err := Send(context.Background(), cfg, []string{"ops@example.com"}, []byte("x"))
	if err == nil {
		t.Fatal("Send accepted plaintext delivery carrying a password to a remote relay")
	}
	if !strings.Contains(err.Error(), "refusing to send credentials") {
		t.Fatalf("Send = %q, want the credentials-over-plaintext refusal", err.Error())
	}
	if strings.Contains(err.Error(), "dial smtp relay") {
		t.Fatalf("Send dialled the relay before refusing: %q", err.Error())
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("the refusal leaked the password: %q", err.Error())
	}
}

// TestSend_PlaintextWithCredentials_AllowedForLocalRelay is the other
// direction: the guard must not break the deployment it was written around.
//
// A relay on the loopback interface is the documented legitimate case for
// plaintext, and a password never leaves the machine, so this must still
// deliver. Without this row the refusal above could be satisfied by refusing
// every authenticated plaintext send, which would break a real deployment
// while the test suite stayed green.
func TestSend_PlaintextWithCredentials_AllowedForLocalRelay(t *testing.T) {
	host, port, closeFn := fakeSMTPServer(t, fakeSMTPOptions{})
	defer closeFn()

	cfg := Config{
		Host: host, Port: port, From: "notify@example.com",
		Username: "user", Password: "hunter2",
		TLSMode: TLSDisabled,
	}
	if err := Send(context.Background(), cfg, []string{"ops@example.com"},
		[]byte("Subject: hi\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("Send to a LOCAL plaintext relay with credentials = %v, want success", err)
	}
}

// TestSend_PlaintextWithoutCredentials_AllowedForRemoteRelay pins that the
// refusal is scoped to the credential, not to plaintext generally: an
// unauthenticated relay is the case sendPlain was written for and must keep
// working regardless of where it lives.
func TestSend_PlaintextWithoutCredentials_AllowedForRemoteRelay(t *testing.T) {
	host, port, closeFn := fakeSMTPServer(t, fakeSMTPOptions{})
	defer closeFn()

	// No Username, so authFor returns nil and nothing secret is on the wire.
	cfg := Config{Host: host, Port: port, From: "notify@example.com", TLSMode: TLSDisabled}
	if err := Send(context.Background(), cfg, []string{"ops@example.com"},
		[]byte("Subject: hi\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("Send to an unauthenticated plaintext relay = %v, want success", err)
	}
}

// TestIsLocalRelay covers the boundary the refusal above turns on. The names
// are the ones net/smtp's PlainAuth exempts; drifting from that set would make
// this package and net/smtp disagree about the same connection.
func TestIsLocalRelay(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"smtp.example.com", false},
		{"10.0.0.5", false},
		{"", false},
	} {
		if got := isLocalRelay(tc.host); got != tc.want {
			t.Errorf("isLocalRelay(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// TestSend_RefusalsDoNotConsumeTheSendBudget pins that both pre-flight
// refusals return immediately rather than after the fallback deadline.
//
// A refusal that took the whole two-minute budget to arrive would be
// indistinguishable, to a background job, from the stalled relay the budget
// exists for.
func TestSend_RefusalsDoNotConsumeTheSendBudget(t *testing.T) {
	shortSendTimeout(t, 2*time.Second)

	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"undefined mode", Config{Host: "relay.example.com", Port: 25, TLSMode: TLSMode(9)}},
		{"credentials over plaintext", Config{Host: "relay.example.com", Port: 25, Username: "u", TLSMode: TLSDisabled}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			err := Send(context.Background(), tc.cfg, []string{"ops@example.com"}, []byte("x"))
			if err == nil {
				t.Fatal("expected a refusal")
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Errorf("refusal took %v; it must be returned before any I/O", elapsed)
			}
		})
	}
}
