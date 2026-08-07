// discovery_resilience_test.go covers the "background job crash" class for the
// suite discovery poller: Start's loop body runs in a goroutine the HOST
// application launches, so a fault in one poll must degrade that poll (loudly)
// rather than terminate the host.
package suite

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureSlog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// faultingClient returns a client whose poll is guaranteed to fault: a nil
// *http.Client dereferences on Do. This stands in for any unexpected fault in
// the poll path — the point is what the loop does with it, not which fault it
// was.
func faultingClient(t *testing.T) *DiscoveryClient {
	t.Helper()
	d := newDiscoveryClient("https://sibling.example.com", Manifest{App: "registry"}, 10*time.Millisecond, testGuard())
	d.httpClient = nil
	return d
}

func TestDiscovery_PanickingPollIsContainedAndLogged(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T, d *DiscoveryClient)
	}{
		{
			name: "a single poll",
			run: func(_ *testing.T, d *DiscoveryClient) {
				d.safePollOnce(context.Background())
			},
		},
		{
			name: "the loop survives repeated faulting polls and still honours ctx",
			run: func(t *testing.T, d *DiscoveryClient) {
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() {
					defer close(done)
					d.Start(ctx)
				}()
				// Long enough for the immediate poll plus several ticks.
				time.Sleep(100 * time.Millisecond)
				cancel()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("the poll loop did not survive a faulting poll")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureSlog(t)
			d := faultingClient(t)

			tc.run(t, d)

			logged := logs.String()
			if !strings.Contains(logged, "level=ERROR") {
				t.Errorf("a recovered panic must be logged at error level, got %q", logged)
			}
			if !strings.Contains(logged, "job=suite-discovery") {
				t.Errorf("the recovery log must name the job, got %q", logged)
			}
			if !strings.Contains(logged, "stack=") {
				t.Errorf("the recovery log must carry a stack trace, got %q", logged)
			}
		})
	}
}

// A recovered poll must leave the client usable: Snapshot is called per request
// by the consuming app, so a poll that faulted and left the state lock held
// would turn a crash into a permanent wedge of every request. pollOnce releases
// d.mu with a deferred unlock, which is what makes recovery safe here.
func TestDiscovery_RecoveredPollDoesNotHoldTheStateLock(t *testing.T) {
	captureSlog(t)
	d := faultingClient(t)

	d.safePollOnce(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = d.Snapshot()
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Snapshot blocked after a recovered poll — the state lock was left held")
	}
}
