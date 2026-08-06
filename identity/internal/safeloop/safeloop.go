// Package safeloop is this module's panic boundary for background jobs.
//
// # Why this exists
//
// Every long-running loop this library ships — the API-key expiry notifier
// (identity/notify), the suite discovery poller (identity/suite), and the
// OAuth-state janitor (identity/auth/oauthstate) — runs inside a HOST
// application's process, and two of the three run in a goroutine the host
// launches for them. A panic raised inside one of those loop bodies is
// therefore not a library error the caller can handle: an unrecovered panic in
// any goroutine terminates the entire process. A single unexpected nil row, a
// malformed cached value, or an out-of-range index on one tick would take down
// a running API server.
//
// Guard turns that into a degraded tick. The loop abandons the iteration that
// faulted and waits for the next one; everything else the host is doing keeps
// running.
//
// # Where it belongs
//
// Guard is applied ONLY at the repeating body of a loop this module owns. It
// is deliberately not smeared across ordinary function calls:
//
//   - A panic on a request path is the host's to recover (net/http already
//     does), and swallowing it here would hide it from that machinery.
//   - A panic during a job's one-time startup is a deterministic wiring or
//     configuration fault. It should stay loud and fail the process at boot,
//     which is when an operator can still see it.
//
// # Recovery is never silent
//
// A swallowed panic is its own defect: it converts a crash that carries a
// stack trace into an invisible, unattributable loss of function, and the job
// then looks healthy while doing nothing. Guard therefore logs the recovered
// value AND the stack at error level before it returns, and reports the
// recovered value to its caller.
package safeloop

import (
	"log/slog"
	"runtime/debug"
)

// Guard runs fn, recovering any panic it raises, logging the recovered value
// and the stack at error level, and reporting the recovered value (nil when fn
// returned normally).
//
// job names the background job in the log line — use the job's own stable
// identifier (e.g. "api-key-expiry-notifier") so the line is greppable and
// attributable to one loop.
//
// The return value exists so the behaviour is directly assertable in a test.
// Production callers ignore it and simply proceed to the next tick.
//
// Guard does not recover a runtime.Goexit (recover reports nil for one), so a
// t.Fatal in a test helper still unwinds normally.
func Guard(job string, fn func()) (recovered any) {
	defer func() {
		if r := recover(); r != nil {
			recovered = r
			// slog.Default() is read here, at call time, rather than captured
			// at init: a host that installs its own handler after importing
			// this library still gets these lines.
			slog.Error("background job recovered from a panic; this run was abandoned, the loop continues",
				"job", job,
				"panic", r,
				"stack", string(debug.Stack()),
			)
		}
	}()
	fn()
	return nil
}
