// janitor_lifetime_test.go covers the STOP path of the goroutine NewMemoryStore
// starts. Close had coverage for idempotence and for clearing entries, but
// nothing asserted the janitor actually exits -- so a regression that left it
// running would have passed the whole suite while leaking a goroutine and a
// time.Ticker per store, which for a Manager built per login flow accumulates
// for the life of the server.
//
// Both directions are here on purpose. The first drives the loop directly, the
// way janitor_resilience_test.go does, and is fully deterministic. The second
// costs a little scheduling tolerance but exercises the REAL construction path,
// which is the one an application uses and the only one that can prove
// NewMemoryStore's goroutine is the one being stopped.

package oauthstate

import (
	"runtime"
	"testing"
	"time"
)

func TestJanitor_ReturnsWhenTheStoreIsClosed(t *testing.T) {
	s := NewMemoryStore(time.Hour, 0)

	// A second janitor over the same stopCh, with an interval long enough that
	// the ticker cannot be what ends it: returning proves the stop signal did.
	returned := make(chan struct{})
	go func() {
		s.janitor(time.Hour, func() {})
		close(returned)
	}()

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("janitor did not return after Close; the goroutine outlives the store")
	}
}

// quietGoroutineCount waits for the count to hold steady before sampling.
// A baseline taken while an earlier test's goroutines are still unwinding reads
// high, which would mask exactly the leak this file is looking for.
func quietGoroutineCount(t *testing.T) int {
	t.Helper()
	prev, stable := -1, 0
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n := runtime.NumGoroutine()
		if n == prev {
			if stable++; stable >= 3 {
				return n
			}
		} else {
			prev, stable = n, 0
		}
		time.Sleep(5 * time.Millisecond)
	}
	return runtime.NumGoroutine()
}

func settleTo(want int, within time.Duration) int {
	deadline := time.Now().Add(within)
	for {
		n := runtime.NumGoroutine()
		if n <= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestMemoryStore_CloseReleasesTheJanitorGoroutine(t *testing.T) {
	// One goroutine is easy to lose in the noise of a package test binary; eight
	// is not. time.Hour guarantees no store here stops for any reason but Close.
	const stores = 8

	base := quietGoroutineCount(t)

	open := make([]*MemoryStore, 0, stores)
	for i := 0; i < stores; i++ {
		open = append(open, NewMemoryStore(time.Hour, 0))
	}

	// Anti-vacuity: if the janitors never started, everything below passes while
	// proving nothing at all.
	if grew := runtime.NumGoroutine() - base; grew < stores {
		t.Fatalf("goroutines grew by %d for %d stores; expected at least one janitor each, so this test cannot show they stop", grew, stores)
	}

	for _, s := range open {
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}

	if got := settleTo(base, 5*time.Second); got > base {
		t.Errorf("goroutines settled at %d, want <= %d: %d janitor(s) outlived Close", got, base, got-base)
	}
}
