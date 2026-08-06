package safeloop

import (
	"bytes"
	"errors"
	"log/slog"
	"runtime"
	"strings"
	"testing"
)

// captureSlog redirects the default slog logger into a buffer for the duration
// of one test, so the "recovery must be LOUD" half of the contract is
// assertable and not merely asserted-by-comment.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestGuard(t *testing.T) {
	tests := []struct {
		name string
		fn   func()
		// wantRecovered is whether Guard must report a recovered value.
		wantRecovered bool
		// wantInLog is a fragment the log line must carry, so a recovery that
		// logged nothing (or logged nothing identifying) fails.
		wantInLog string
	}{
		{
			name:          "normal return is neither recovered nor logged",
			fn:            func() {},
			wantRecovered: false,
		},
		{
			name:          "explicit string panic",
			fn:            func() { panic("boom") },
			wantRecovered: true,
			wantInLog:     "boom",
		},
		{
			name:          "explicit error panic",
			fn:            func() { panic(errors.New("kaput")) },
			wantRecovered: true,
			wantInLog:     "kaput",
		},
		{
			name: "nil pointer dereference (the shape of issue #148)",
			fn: func() {
				type row struct{ Email string }
				var r *row
				_ = r.Email
			},
			wantRecovered: true,
			wantInLog:     "nil pointer dereference",
		},
		{
			name: "index out of range",
			fn: func() {
				s := []int{}
				i := 3
				_ = s[i]
			},
			wantRecovered: true,
			wantInLog:     "index out of range",
		},
		{
			name: "close of a closed channel (the shape of issue #150)",
			fn: func() {
				ch := make(chan struct{})
				close(ch)
				close(ch)
			},
			wantRecovered: true,
			wantInLog:     "close of closed channel",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureSlog(t)

			got := Guard("test-job", tc.fn)

			if (got != nil) != tc.wantRecovered {
				t.Fatalf("Guard returned %v, wantRecovered=%v", got, tc.wantRecovered)
			}

			logged := buf.String()
			if !tc.wantRecovered {
				if logged != "" {
					t.Errorf("a normal return must not log anything, got %q", logged)
				}
				return
			}
			if !strings.Contains(logged, "level=ERROR") {
				t.Errorf("recovery must be logged at error level, got %q", logged)
			}
			if !strings.Contains(logged, "job=test-job") {
				t.Errorf("recovery must name the job, got %q", logged)
			}
			if !strings.Contains(logged, tc.wantInLog) {
				t.Errorf("recovery log must carry %q, got %q", tc.wantInLog, logged)
			}
			if !strings.Contains(logged, "stack=") || !strings.Contains(logged, "safeloop.Guard") {
				t.Errorf("recovery log must carry a stack trace, got %q", logged)
			}
		})
	}
}

func TestGuard_RunsTheBody(t *testing.T) {
	captureSlog(t)
	ran := false
	if got := Guard("test-job", func() { ran = true }); got != nil {
		t.Fatalf("Guard reported %v for a body that did not panic", got)
	}
	if !ran {
		t.Error("Guard did not run the body")
	}
}

func TestGuard_ReportsThePanicValue(t *testing.T) {
	captureSlog(t)
	sentinel := errors.New("sentinel")
	got := Guard("test-job", func() { panic(sentinel) })
	if !errors.Is(got.(error), sentinel) {
		t.Errorf("Guard reported %v, want the panic value itself", got)
	}
}

// A runtime.Goexit is not a panic, and recover() reports nil for one. Guard
// must not pretend to have recovered it (nor log a phantom fault) — this is
// what keeps t.Fatal inside a guarded test helper behaving normally.
func TestGuard_DoesNotRecoverGoexit(t *testing.T) {
	buf := captureSlog(t)

	returned := false
	done := make(chan struct{})
	go func() {
		defer close(done)
		Guard("test-job", runtime.Goexit)
		returned = true
	}()
	<-done

	if returned {
		t.Error("Guard returned normally from a runtime.Goexit; it must let the goroutine unwind")
	}
	if logged := buf.String(); logged != "" {
		t.Errorf("a Goexit is not a panic and must not be logged as one, got %q", logged)
	}
}
