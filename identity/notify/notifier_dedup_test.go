package notify

// notifier_dedup_test.go covers claimDedup and its wiring into Notify (#157):
// a caller that sets Event.DedupKey must not fan out to channels when
// another caller (in the same process or a sibling replica) already holds a
// live claim on the same key, and a caller that never sets it must see the
// claim store touched not at all.

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

const claimSQL = `INSERT INTO notify_dedup_claims`
const pruneSQL = `DELETE FROM notify_dedup_claims`

// expectPrune stubs the self-prune ClaimDedup fires after every claim
// attempt (see NotifyDedupRepository.maybePruneExpiredClaims). A fresh
// repository's throttle is zero-valued -- "prune on the next claim" -- so
// every test below that reaches the claim store hits this exactly once;
// stub it as a clean no-op batch rather than let it surface as an
// unexpected-call error on the mock.
func expectPrune(mock sqlmock.Sqlmock) {
	mock.ExpectExec(pruneSQL).WillReturnResult(sqlmock.NewResult(0, 0))
}

// TestClaimDedup_EmptyKeyNeverTouchesTheClaimStore is the zero-cost-default
// guarantee: a caller that never sets DedupKey must not pay a DB round trip
// for it. sqlmock fails the test on any unexpected statement, so leaving no
// expectations set is itself the assertion.
func TestClaimDedup_EmptyKeyNeverTouchesTheClaimStore(t *testing.T) {
	repo, mock := newChannelRepo(t)
	n := NewNotifier(repo, nil, nil, nil, Options{})

	if !n.claimDedup(context.Background(), Event{Type: "x"}) {
		t.Fatal("claimDedup(empty key) = false, want true")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("empty DedupKey issued a query it should not have: %v", err)
	}
}

// TestClaimDedup_WinsWhenRowReturned is the ordinary win path: the UPSERT
// returned a row, so this caller claimed the key and should deliver.
func TestClaimDedup_WinsWhenRowReturned(t *testing.T) {
	repo, mock := newChannelRepo(t)
	n := NewNotifier(repo, nil, nil, nil, Options{})

	mock.ExpectQuery(claimSQL).
		WithArgs("scanner-update:trivy:v1.2.3", defaultDedupTTL.Seconds()).
		WillReturnRows(sqlmock.NewRows([]string{"dedup_key"}).AddRow("scanner-update:trivy:v1.2.3"))
	expectPrune(mock)

	if !n.claimDedup(context.Background(), Event{Type: "x", DedupKey: "scanner-update:trivy:v1.2.3"}) {
		t.Fatal("claimDedup(won) = false, want true")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// TestClaimDedup_LosesWhenNoRowReturned is the race-lost path: another
// caller's claim is still live, so this caller's conditional UPDATE matched
// no row and the driver reports sql.ErrNoRows on Scan.
func TestClaimDedup_LosesWhenNoRowReturned(t *testing.T) {
	repo, mock := newChannelRepo(t)
	n := NewNotifier(repo, nil, nil, nil, Options{})

	mock.ExpectQuery(claimSQL).
		WithArgs("run_failed:org-1", defaultDedupTTL.Seconds()).
		WillReturnError(sql.ErrNoRows)
	expectPrune(mock)

	if n.claimDedup(context.Background(), Event{Type: "x", DedupKey: "run_failed:org-1"}) {
		t.Fatal("claimDedup(lost) = true, want false")
	}
}

// TestClaimDedup_CustomTTLIsForwarded proves DedupTTL actually reaches the
// claim statement rather than being silently ignored in favor of the default.
func TestClaimDedup_CustomTTLIsForwarded(t *testing.T) {
	repo, mock := newChannelRepo(t)
	n := NewNotifier(repo, nil, nil, nil, Options{})

	custom := 15 * time.Minute
	mock.ExpectQuery(claimSQL).
		WithArgs("k", custom.Seconds()).
		WillReturnRows(sqlmock.NewRows([]string{"dedup_key"}).AddRow("k"))
	expectPrune(mock)

	if !n.claimDedup(context.Background(), Event{Type: "x", DedupKey: "k", DedupTTL: custom}) {
		t.Fatal("claimDedup = false, want true")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// TestClaimDedup_StoreErrorFailsOpen: a claim-store error (a connection
// blip, a lock wait timing out) must not silently swallow a legitimate
// alert. Delivering is the documented fail-open direction -- see
// claimDedup's doc comment.
func TestClaimDedup_StoreErrorFailsOpen(t *testing.T) {
	repo, mock := newChannelRepo(t)
	n := NewNotifier(repo, nil, nil, nil, Options{})

	mock.ExpectQuery(claimSQL).
		WithArgs("k", defaultDedupTTL.Seconds()).
		WillReturnError(errors.New(`pq: relation "notify_dedup_claims" does not exist`))
	expectPrune(mock)

	if !n.claimDedup(context.Background(), Event{Type: "x", DedupKey: "k"}) {
		t.Fatal("claimDedup(store error) = false, want true (fail open)")
	}
}

// TestNotify_SkipsChannelFanOutWhenClaimLost is the end-to-end regression:
// Notify itself, not just claimDedup in isolation, must not proceed to
// ListEnabledForEvent (and therefore never deliver to any channel) when the
// claim is lost.
//
// sqlmock does reject an unmatched query (there is no ListEnabledForEvent
// expectation registered), but that rejection only reaches
// ChannelRepository as an error, which Notify logs and swallows -- it never
// reaches this test's own assertions, so ExpectationsWereMet alone proves
// nothing here (a version of Notify that ignored claimDedup's result
// entirely still passes it, because the one expectation that WAS registered
// -- the claim query -- is still satisfied regardless). Capturing the log
// output is what actually distinguishes "never attempted" from "attempted
// and failed": only the latter logs "failed to load notification
// channels". Verified: reverting the claimDedup gate in Notify makes this
// assertion fail with that exact message present.
func TestNotify_SkipsChannelFanOutWhenClaimLost(t *testing.T) {
	repo, mock := newChannelRepo(t)

	var logs bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(restore)

	n := NewNotifier(repo, nil, nil, nil, Options{})

	mock.ExpectQuery(claimSQL).
		WithArgs("run_failed:org-1", defaultDedupTTL.Seconds()).
		WillReturnError(sql.ErrNoRows)
	expectPrune(mock)

	n.Notify(context.Background(), Event{Type: "run_failed", DedupKey: "run_failed:org-1"})

	if strings.Contains(logs.String(), "failed to load notification channels") {
		t.Errorf("Notify attempted ListEnabledForEvent after losing the claim; log output:\n%s", logs.String())
	}
}
