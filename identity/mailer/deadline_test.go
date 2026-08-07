// deadline_test.go covers the invariant that Send always returns. Only the TCP
// dial is bounded by context cancellation; net/smtp is not context-aware, so a
// relay that accepts the connection and then stalls is bounded solely by the
// connection deadline Send derives from the context — which is why Send must
// supply one of its own when the caller's context carries none.
package mailer

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// stalledRelay accepts TCP connections and then says nothing at all — never
// even the 220 greeting. This is the misconfigured/overloaded relay failure
// mode: the dial succeeds, so nothing the dialer bounds is ever reached.
func stalledRelay(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// Hold accepted connections open (and silent) until the test ends.
	conns := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns <- c
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		close(conns)
		for c := range conns {
			_ = c.Close()
		}
	})

	h, p, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", p, err)
	}
	return h, n
}

// shortSendTimeout shrinks the package's fallback deadline so a test can
// observe it firing without waiting the production budget.
func shortSendTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	sendTimeoutOverride.Store(int64(d))
	t.Cleanup(func() { sendTimeoutOverride.Store(0) })
}

func TestSend_StalledRelay_TimesOutInsteadOfBlocking(t *testing.T) {
	host, port := stalledRelay(t)

	tests := []struct {
		name string
		// ctx is the caller's context. The point of the table is that BOTH a
		// deadline-less background context (what a background job holds) and a
		// caller-supplied deadline end the call.
		ctx    func(t *testing.T) context.Context
		useTLS bool
		// budget is how long the call may take before the test calls it wedged.
		budget time.Duration
	}{
		{
			name:   "plaintext, caller context has no deadline (a background job's context)",
			ctx:    func(*testing.T) context.Context { return context.Background() },
			budget: 5 * time.Second,
		},
		{
			name: "plaintext, caller supplies its own deadline",
			ctx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				t.Cleanup(cancel)
				return ctx
			},
			budget: 5 * time.Second,
		},
		{
			name: "TLSRequired, caller context has no deadline (TLS dial fails, STARTTLS path stalls)",
			ctx:  func(*testing.T) context.Context { return context.Background() },
			// The implicit-TLS dial handshakes against a silent server, so it
			// consumes the fallback budget before sendStartTLS gets its own.
			useTLS: true,
			budget: 10 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			shortSendTimeout(t, 300*time.Millisecond)
			cfg := Config{Host: host, Port: port, From: "noreply@example.com", TLSMode: TLSModeForUseTLS(tc.useTLS)}

			done := make(chan error, 1)
			start := time.Now()
			go func() {
				done <- Send(tc.ctx(t), cfg, []string{"ops@example.com"}, []byte("Subject: x\r\n\r\nbody\r\n"))
			}()

			select {
			case err := <-done:
				elapsed := time.Since(start)
				if err == nil {
					t.Fatalf("Send succeeded against a relay that never replies (after %v)", elapsed)
				}
				if !isTimeout(err) {
					t.Errorf("Send returned %v after %v; want a timeout error", err, elapsed)
				}
			case <-time.After(tc.budget):
				t.Fatalf("Send did not return within %v — the caller is wedged", tc.budget)
			}
		})
	}
}

// isTimeout reports whether err is (or wraps) a deadline/timeout, whichever
// layer surfaced it: the dialer's context, the connection deadline, or a
// net.Error marked temporary-timeout.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// net/smtp wraps some I/O failures in textproto errors that lose the
	// net.Error identity; fall back to the message.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded")
}

// A caller-supplied deadline must be honoured as-is; Send must not widen it to
// its own fallback.
func TestSend_CallerDeadlineIsNotWidened(t *testing.T) {
	host, port := stalledRelay(t)
	shortSendTimeout(t, time.Hour) // absurdly wide: only the caller's bound can end this

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	cfg := Config{Host: host, Port: port, From: "noreply@example.com", TLSMode: TLSDisabled}
	done := make(chan error, 1)
	go func() {
		done <- Send(ctx, cfg, []string{"ops@example.com"}, []byte("Subject: x\r\n\r\nbody\r\n"))
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Send succeeded against a relay that never replies")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Send ignored the caller's deadline")
	}
}

// An already-cancelled context must fail immediately rather than inherit the
// fallback budget.
func TestSend_CancelledContextReturnsImmediately(t *testing.T) {
	host, port := stalledRelay(t)
	shortSendTimeout(t, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := Config{Host: host, Port: port, From: "noreply@example.com", TLSMode: TLSDisabled}
	start := time.Now()
	err := Send(ctx, cfg, []string{"ops@example.com"}, []byte("Subject: x\r\n\r\nbody\r\n"))
	if err == nil {
		t.Fatal("Send with a cancelled context should fail")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Send took %v with an already-cancelled context", elapsed)
	}
}
