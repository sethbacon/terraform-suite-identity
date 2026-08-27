package notify

// notifier_scope_test.go covers the DELIVERY surface's organization scope
// (#246).
//
// v0.31.0 gave ChannelRepository an optional scope and v0.32.0 gave Notify one.
// SendTest did not get it, and that is the sharper gap of the two: channelID
// comes from the caller's request, so an unscoped GetByID there is an IDOR on a
// SENDING surface -- an administrator of one organization supplying another
// organization's channel id makes this service POST to that organization's
// Slack or webhook URL.
//
// These tests assert the SQL, because that is where the scope either is or is
// not. A test that only checked "SendTest returned an error" would pass against
// a version that fetched the channel unscoped and failed for some other reason.

import (
	"context"
	"database/sql/driver"
	"errors"
	"os"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/sethbacon/terraform-suite-identity/identity/store"
)

// notifierFor builds a Notifier over a mock whose SQL is compared exactly.
func notifierFor(t *testing.T) (*Notifier, sqlmock.Sqlmock) {
	t.Helper()
	repo, mock := newScopedChannelRepo(t)
	return NewNotifier(repo, nil, nil, nil, Options{TestMessage: "test"}), mock
}

// TestSendTestScopesTheChannelLookup is the regression.
func TestSendTestScopesTheChannelLookup(t *testing.T) {
	n, mock := notifierFor(t)

	scoped := `SELECT ` + channelColumns +
		` FROM notification_channels WHERE id = $1 AND organization_id = ANY($2)`
	mock.ExpectQuery(scoped).
		WithArgs(driver.Value(scopeTestChannelID), []string{scopeTestOrgA}).
		WillReturnError(store.ErrNotFound)

	err := n.SendTest(context.Background(), scopeTestChannelID,
		WithOrgScope(store.OrgScopeOrganizations(scopeTestOrgA)))

	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want store.ErrNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("SendTest did not issue the scoped lookup: %v.\n"+
			"channelID comes from the caller's request, so an unscoped GetByID lets an "+
			"administrator of one organization make this service POST to another "+
			"organization's webhook (#246).", err)
	}
}

// TestSendTestWithoutAScopeIsUnscoped keeps the option variadic.
//
// terraform-registry does not partition its channels and passes nothing; it
// must keep working exactly as before. An option that became mandatory would
// break it at compile time, which is what "additive, as v0.31.0 was" means.
func TestSendTestWithoutAScopeIsUnscoped(t *testing.T) {
	n, mock := notifierFor(t)

	unscoped := `SELECT ` + channelColumns + ` FROM notification_channels WHERE id = $1`
	mock.ExpectQuery(unscoped).
		WithArgs(driver.Value(scopeTestChannelID)).
		WillReturnError(store.ErrNotFound)

	if err := n.SendTest(context.Background(), scopeTestChannelID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want store.ErrNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("an unscoped SendTest did not issue the unscoped statement: %v", err)
	}
}

// TestOutOfScopeChannelIsNotFoundRatherThanForbidden.
//
// Reporting "forbidden" would confirm the channel exists, which is the
// disclosure the scope exists to prevent. The scoped GetByID already answers
// not-found; this pins that SendTest passes it through unchanged rather than
// translating it.
func TestOutOfScopeChannelIsNotFoundRatherThanForbidden(t *testing.T) {
	n, mock := notifierFor(t)

	scoped := `SELECT ` + channelColumns +
		` FROM notification_channels WHERE id = $1 AND organization_id = ANY($2)`
	// The channel belongs to org B; the caller is scoped to org A, so the
	// predicate excludes it and the row is simply absent.
	mock.ExpectQuery(scoped).
		WithArgs(driver.Value(scopeTestChannelID), []string{scopeTestOrgA}).
		WillReturnError(store.ErrNotFound)

	err := n.SendTest(context.Background(), scopeTestChannelID,
		WithOrgScope(store.OrgScopeOrganizations(scopeTestOrgA)))

	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want store.ErrNotFound -- a channel outside the scope must be "+
			"indistinguishable from one that does not exist", err)
	}
}

// TestEveryRepositoryCallFromTheNotifierForwardsOptions is the class guard.
//
// The defect was not that one function lacked a parameter; it was that the
// delivery surface reached the repository at three places and only one of them
// carried the scope. A fourth call added later without the option would be
// invisible -- it would work, and it would work for everyone.
func TestEveryRepositoryCallFromTheNotifierForwardsOptions(t *testing.T) {
	src := readNotifierSource(t)
	for _, call := range []string{"ListEnabledForEvent", "GetByID", "RecordDelivery"} {
		found := false
		for _, line := range splitLines(src) {
			if !containsAll(line, "n.repo."+call+"(") {
				continue
			}
			found = true
			if !containsAll(line, "opts...") {
				t.Errorf("the notifier calls n.repo.%s without forwarding opts:\n  %s\n\n"+
					"Every repository call from the delivery surface must carry the caller's "+
					"scope, or a partitioned consumer gets a scoped read here and an unscoped "+
					"one there (#246).", call, trimSpace(line))
			}
		}
		if !found {
			t.Errorf("no call to n.repo.%s was found. If it was renamed, point this guard at the "+
				"new name rather than deleting it.", call)
		}
	}

	// And the INTERNAL threading, which is where the scope is actually lost.
	//
	// The repository calls above are one level below deliver, and a mutation
	// that stopped deliver forwarding opts to record left every one of them
	// looking correct -- record still had `opts...`, it just received none.
	// That is the shape of a threading bug: each hop is right and the chain is
	// broken.
	recordCalls := 0
	for _, line := range splitLines(src) {
		l := trimSpace(line)
		if !containsAll(l, "n.record(ctx,") || containsAll(l, "func ") {
			continue
		}
		recordCalls++
		if !containsAll(l, "opts...") {
			t.Errorf("deliver calls n.record without forwarding opts:\n  %s\n\n"+
				"The delivery record would then be written unscoped even though the channel was "+
				"loaded under a scope.", l)
		}
	}
	if recordCalls == 0 {
		t.Error("no n.record call sites were found; this half of the guard is checking nothing")
	}

	deliverCalls := 0
	for _, line := range splitLines(src) {
		l := trimSpace(line)
		if !containsAll(l, "n.deliver(ctx,") || containsAll(l, "func ") {
			continue
		}
		deliverCalls++
		if !containsAll(l, "opts...") {
			t.Errorf("a caller invokes n.deliver without forwarding opts:\n  %s", l)
		}
	}
	if deliverCalls == 0 {
		t.Error("no n.deliver call sites were found; this half of the guard is checking nothing")
	}
}

func readNotifierSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("notifier.go")
	if err != nil {
		t.Fatalf("read notifier.go: %v", err)
	}
	return string(b)
}

func splitLines(s string) []string { return strings.Split(s, "\n") }
func trimSpace(s string) string    { return strings.TrimSpace(s) }
func containsAll(hay string, needles ...string) bool {
	for _, n := range needles {
		if !strings.Contains(hay, n) {
			return false
		}
	}
	return true
}
