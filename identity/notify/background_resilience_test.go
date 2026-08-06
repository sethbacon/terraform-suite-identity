// background_resilience_test.go covers the "background job crash and wedge"
// class for identity/notify: the module owns a loop body that a HOST process
// runs in its own goroutine, so a fault in it must degrade one tick (loudly)
// rather than terminate the host, shutdown must be safe to repeat and to race,
// and no call the loop makes may block without a bound.
package notify

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/sethbacon/terraform-suite-identity/identity/crypto"
	"github.com/sethbacon/terraform-suite-identity/identity/httpsafe"
	identitymodels "github.com/sethbacon/terraform-suite-identity/identity/models"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// syncBuffer is a bytes.Buffer safe to write from a background goroutine while
// the test reads it.
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

// captureSlog redirects the default slog logger (which safeloop.Guard writes
// to) for the duration of one test.
func captureSlog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// shortDBTimeout shrinks the notifier's per-query bound so the "a stalled
// query does not wedge the loop" assertion runs in milliseconds.
func shortDBTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	dbTimeoutOverride.Store(int64(d))
	t.Cleanup(func() { dbTimeoutOverride.Store(0) })
}

// stubAPIKeyRepo is a scriptable apiKeyRepo: it can fault, stall, or return a
// fixed key set, none of which a sqlmock-backed repository can be made to do.
type stubAPIKeyRepo struct {
	mu         sync.Mutex
	findCalls  int
	claimCalls int

	keys      []*identitymodels.APIKey
	findErr   error
	findPanic bool
	// findDelay stalls the query, honouring ctx so a bounded caller unblocks
	// early and an unbounded one waits the whole time.
	findDelay time.Duration
	claimed   bool
}

func (s *stubAPIKeyRepo) FindExpiringKeys(ctx context.Context, _ int) ([]*identitymodels.APIKey, error) {
	s.mu.Lock()
	s.findCalls++
	s.mu.Unlock()
	if s.findPanic {
		panic("simulated fault while scanning expiring keys")
	}
	if s.findDelay > 0 {
		select {
		case <-time.After(s.findDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.keys, s.findErr
}

func (s *stubAPIKeyRepo) ClaimExpiryNotification(_ context.Context, _ string) (bool, error) {
	s.mu.Lock()
	s.claimCalls++
	s.mu.Unlock()
	return s.claimed, nil
}

func (s *stubAPIKeyRepo) calls() (find, claim int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.findCalls, s.claimCalls
}

// stubUserRepo reports the "row is gone" contract of the real UserRepository:
// (nil, nil), not an error.
type stubUserRepo struct {
	user *identitymodels.User
	err  error
}

func (s *stubUserRepo) GetUserByID(context.Context, string) (*identitymodels.User, error) {
	return s.user, s.err
}

func newTestNotifierJob(t *testing.T, keyRepo apiKeyRepo, users userRepo) *APIKeyExpiryNotifier {
	t.Helper()
	return NewAPIKeyExpiryNotifier(keyRepo, users, newExpiryConfigProvider(newExpiryConfig(true, "smtp.example.com")), testExpiryOpts)
}

func expiringKey(id, userID string) *identitymodels.APIKey {
	expiresAt := time.Now().Add(3 * 24 * time.Hour)
	return &identitymodels.APIKey{
		ID:        id,
		UserID:    &userID,
		Name:      "CI Key",
		KeyPrefix: "tfr_abc",
		ExpiresAt: &expiresAt,
	}
}

// ---------------------------------------------------------------------------
// A panicking tick must not propagate out of the loop, and must be logged
// (issue #148's failure mode, generalized to the whole loop body)
// ---------------------------------------------------------------------------

func TestExpiryNotifier_PanickingTickIsContainedAndLogged(t *testing.T) {
	tests := []struct {
		name string
		// run drives one tick (or the whole loop) and must return without the
		// panic escaping.
		run func(t *testing.T, n *APIKeyExpiryNotifier)
	}{
		{
			name: "single tick",
			run: func(_ *testing.T, n *APIKeyExpiryNotifier) {
				n.runTick(context.Background())
			},
		},
		{
			name: "the loop survives the panicking immediate check and still stops",
			run: func(t *testing.T, n *APIKeyExpiryNotifier) {
				done := make(chan struct{})
				go func() {
					defer close(done)
					_ = n.Start(context.Background())
				}()
				// The immediate check panics; the loop must still be alive to
				// observe Stop.
				time.Sleep(50 * time.Millisecond)
				_ = n.Stop()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("loop did not survive a panicking tick (never reached Stop)")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureSlog(t)
			repo := &stubAPIKeyRepo{findPanic: true}
			n := newTestNotifierJob(t, repo, nil)

			tc.run(t, n)

			find, _ := repo.calls()
			if find == 0 {
				t.Fatal("the check never ran, so nothing was proven")
			}
			logged := logs.String()
			if !strings.Contains(logged, "level=ERROR") {
				t.Errorf("a recovered panic must be logged at error level, got %q", logged)
			}
			if !strings.Contains(logged, "job=api-key-expiry-notifier") {
				t.Errorf("the recovery log must name the job, got %q", logged)
			}
			if !strings.Contains(logged, "simulated fault while scanning expiring keys") {
				t.Errorf("the recovery log must carry the panic value, got %q", logged)
			}
			if !strings.Contains(logged, "stack=") {
				t.Errorf("the recovery log must carry a stack trace, got %q", logged)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Stop is idempotent and concurrency-safe (issue #150)
// ---------------------------------------------------------------------------

func TestExpiryNotifier_Stop_IsIdempotent(t *testing.T) {
	tests := []struct {
		name string
		stop func(n *APIKeyExpiryNotifier)
	}{
		{
			name: "twice in sequence",
			stop: func(n *APIKeyExpiryNotifier) {
				_ = n.Stop()
				_ = n.Stop()
			},
		},
		{
			name: "many times in sequence",
			stop: func(n *APIKeyExpiryNotifier) {
				for i := 0; i < 10; i++ {
					_ = n.Stop()
				}
			},
		},
		{
			name: "concurrently from many goroutines (a shutdown racing a signal handler)",
			stop: func(n *APIKeyExpiryNotifier) {
				var wg sync.WaitGroup
				start := make(chan struct{})
				for i := 0; i < 32; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						_ = n.Stop()
					}()
				}
				close(start) // release them all at once
				wg.Wait()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := newTestNotifierJob(t, nil, nil)
			tc.stop(n) // must not panic
			if err := n.Stop(); err != nil {
				t.Errorf("Stop returned %v, want nil", err)
			}
			if !n.isStopped() {
				t.Error("the notifier should report itself stopped")
			}
		})
	}
}

func TestExpiryNotifier_Stop_WhileLoopRunning_ThenStopAgain(t *testing.T) {
	repo := &stubAPIKeyRepo{}
	n := newTestNotifierJob(t, repo, nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = n.Start(context.Background())
	}()
	time.Sleep(50 * time.Millisecond)

	_ = n.Stop()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
	_ = n.Stop() // the second, post-exit Stop must not panic either
}

// ---------------------------------------------------------------------------
// Start/Stop ordering
// ---------------------------------------------------------------------------

func TestExpiryNotifier_StartStopOrdering(t *testing.T) {
	tests := []struct {
		name string
		// drive returns after exercising the ordering under test.
		drive func(t *testing.T, n *APIKeyExpiryNotifier)
		// wantChecks is how many expiry checks may have run in total.
		wantChecks int
	}{
		{
			name: "Stop() before Start(): Start does no work and returns",
			drive: func(t *testing.T, n *APIKeyExpiryNotifier) {
				_ = n.Stop()
				mustReturnQuickly(t, func() { _ = n.Start(context.Background()) })
			},
			wantChecks: 0,
		},
		{
			name: "Start() after a Stop() that ended a running loop: returns without restarting",
			drive: func(t *testing.T, n *APIKeyExpiryNotifier) {
				done := make(chan struct{})
				go func() {
					defer close(done)
					_ = n.Start(context.Background())
				}()
				time.Sleep(50 * time.Millisecond)
				_ = n.Stop()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("Start did not return after Stop")
				}
				mustReturnQuickly(t, func() { _ = n.Start(context.Background()) })
			},
			wantChecks: 1, // only the first loop's immediate check
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := &stubAPIKeyRepo{}
			n := newTestNotifierJob(t, repo, nil)

			tc.drive(t, n)

			if find, _ := repo.calls(); find != tc.wantChecks {
				t.Errorf("ran %d expiry check(s), want %d", find, tc.wantChecks)
			}
		})
	}
}

func mustReturnQuickly(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("call did not return promptly")
	}
}

// ---------------------------------------------------------------------------
// A stalled query must not wedge the loop (the #146 failure mode, applied to
// the job's own database round-trips)
// ---------------------------------------------------------------------------

func TestExpiryNotifier_StalledQueryDoesNotWedgeTheLoop(t *testing.T) {
	shortDBTimeout(t, 50*time.Millisecond)
	// Ten seconds is "forever" relative to the bound: without one, runCheck
	// would still be inside the query when the assertion below fires.
	repo := &stubAPIKeyRepo{findDelay: 10 * time.Second}
	n := newTestNotifierJob(t, repo, nil)

	start := time.Now()
	mustReturnQuickly(t, func() { n.runCheck(context.Background()) })
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("runCheck took %v against a stalled query; the per-query bound did not apply", elapsed)
	}
	if find, _ := repo.calls(); find != 1 {
		t.Errorf("FindExpiringKeys called %d time(s), want 1", find)
	}
}

// ---------------------------------------------------------------------------
// Nil dereferences reachable from the loop body (issue #148, first finding)
// ---------------------------------------------------------------------------

// The real UserRepository reports a missing row as (nil, nil). api_keys.user_id
// is ON DELETE SET NULL, so deleting a user whose key is inside the warning
// window lands exactly here — a routine administrative action that must not
// take the host down.
func TestExpiryNotifier_RunCheck_DeletedUser_IsSkipped(t *testing.T) {
	apiKeyRepo, apiKeyMock := newAPIKeyRepoForNotifier(t)
	userRepo, userMock := newUserRepoForNotifier(t)
	cfg := newExpiryConfig(true, "smtp.example.com")
	n := NewAPIKeyExpiryNotifier(apiKeyRepo, userRepo, newExpiryConfigProvider(cfg), testExpiryOpts)

	expiresAt := time.Now().Add(3 * 24 * time.Hour)
	userID := "user-1"
	apiKeyMock.ExpectQuery("SELECT.*FROM api_keys").
		WillReturnRows(sqlmock.NewRows(findExpiringKeysCols).
			AddRow("key-1", &userID, "org-1", "CI Key", nil,
				"hash", "tfr_abc", []byte(`["modules:read"]`), &expiresAt, nil, nil, time.Now()))
	// Zero rows for the user: GetUserByID turns sql.ErrNoRows into (nil, nil).
	userMock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(userColsForNotifier))

	// No ExpectExec is registered for the claim: reaching it would be a
	// sqlmock error, proving the key was skipped rather than processed.
	n.runCheck(context.Background()) // must not panic

	if err := apiKeyMock.ExpectationsWereMet(); err != nil {
		t.Errorf("api_key unmet expectations: %v", err)
	}
	if err := userMock.ExpectationsWereMet(); err != nil {
		t.Errorf("user unmet expectations: %v", err)
	}
}

func TestExpiryNotifier_RunCheck_NilDereferencesInTheLoopBody(t *testing.T) {
	userID := "user-1"
	keyNoExpiry := &identitymodels.APIKey{ID: "key-2", UserID: &userID, Name: "No Expiry"}

	tests := []struct {
		name       string
		keys       []*identitymodels.APIKey
		users      userRepo
		wantClaims int
	}{
		{
			name:  "a nil key in the result set is skipped",
			keys:  []*identitymodels.APIKey{nil},
			users: &stubUserRepo{user: &identitymodels.User{Email: "ops@example.com"}},
		},
		{
			name:  "a key with no expiry is skipped rather than dereferenced",
			keys:  []*identitymodels.APIKey{keyNoExpiry},
			users: &stubUserRepo{user: &identitymodels.User{Email: "ops@example.com"}},
		},
		{
			name:  "a deleted owner reported as (nil, nil) is skipped",
			keys:  []*identitymodels.APIKey{expiringKey("key-1", userID)},
			users: &stubUserRepo{user: nil, err: nil},
		},
		{
			name:  "a user lookup error is skipped",
			keys:  []*identitymodels.APIKey{expiringKey("key-1", userID)},
			users: &stubUserRepo{err: errors.New("db connection lost")},
		},
		{
			name:  "a nil user repository does not dereference",
			keys:  []*identitymodels.APIKey{expiringKey("key-1", userID)},
			users: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := &stubAPIKeyRepo{keys: tc.keys}
			n := newTestNotifierJob(t, repo, tc.users)

			n.runCheck(context.Background()) // must not panic

			if _, claims := repo.calls(); claims != tc.wantClaims {
				t.Errorf("claimed %d notification(s), want %d", claims, tc.wantClaims)
			}
		})
	}
}

func TestExpiryNotifier_RunCheck_NilAPIKeyRepo(t *testing.T) {
	n := newTestNotifierJob(t, nil, nil)
	n.runCheck(context.Background()) // must not panic
}

// ---------------------------------------------------------------------------
// Nil TokenCipher on the delivery path (issue #148, second finding)
// ---------------------------------------------------------------------------

func TestNotifier_NilTokenCipher_ErrorsInsteadOfPanicking(t *testing.T) {
	// A real cipher only to produce a realistic non-empty stored target; the
	// Notifier under test is built without one.
	tc, err := crypto.NewTokenCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	enc, err := tc.Seal("https://hooks.example.com/x")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tests := []struct {
		name   string
		target string
	}{
		{name: "a real admin-configured (encrypted) target", target: enc},
		{name: "a corrupt target", target: "not-valid-ciphertext"},
	}

	for _, tc2 := range tests {
		t.Run(tc2.name, func(t *testing.T) {
			db, _, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })

			n := NewNotifier(NewChannelRepository(db), nil, nil, httpsafe.MustGuard("127.0.0.1"), testOpts)

			got, err := n.decryptTarget(&NotificationChannel{EncryptedTarget: tc2.target})
			if err == nil {
				t.Fatalf("decryptTarget returned (%q, nil); a missing encryption key must be an error", got)
			}
			if !strings.Contains(err.Error(), "encryption key not configured") {
				t.Errorf("error = %v, want it to name the missing encryption key", err)
			}
		})
	}
}

func TestNotifier_NilTokenCipher_DeliverRecordsFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	n := NewNotifier(NewChannelRepository(db), nil, nil, httpsafe.MustGuard("127.0.0.1"), testOpts)
	mock.ExpectExec("UPDATE notification_channels SET last_status").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = n.deliver(context.Background(), &NotificationChannel{
		ID: testChannelID1, Name: "ops", Type: "webhook", EncryptedTarget: "ciphertext",
	}, "Title", "Message")
	if err == nil {
		t.Fatal("deliver should fail when no encryption key is configured")
	}
	if mErr := mock.ExpectationsWereMet(); mErr != nil {
		t.Errorf("the failure should have been recorded: %v", mErr)
	}
}

// ---------------------------------------------------------------------------
// Nil ChannelRepository — the same "the constructor tolerates nil" trap, on a
// path documented as safe to call from a goroutine
// ---------------------------------------------------------------------------

func TestNotifier_NilRepo_DoesNotPanic(t *testing.T) {
	n := NewNotifier(nil, nil, nil, httpsafe.MustGuard("127.0.0.1"), testOpts)

	n.Notify(context.Background(), Event{Type: testEventType, Title: "t", Message: "m"}) // must not panic

	if err := n.SendTest(context.Background(), testChannelID1); err == nil {
		t.Error("SendTest with no channel repository should return an error")
	}
	n.record(context.Background(), testChannelID1, errors.New("x")) // must not panic
}
