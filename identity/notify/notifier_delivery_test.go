package notify

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/sethbacon/terraform-suite-identity/identity/crypto"
	"github.com/sethbacon/terraform-suite-identity/identity/httpsafe"
)

const (
	testChannelID1 = "11111111-1111-1111-1111-111111111111"
	testChannelID2 = "22222222-2222-2222-2222-222222222222"
	testEventType  = "test_event"
)

var testOpts = Options{Source: "terraform-suite-test", TestMessage: "This is a test."}

var notifyChannelCols = []string{
	"id", "name", "type", "encrypted_target", "events", "enabled",
	"last_status", "last_error", "last_sent_at", "created_at", "updated_at",
}

// newTestNotifier builds a Notifier over a sqlmock-backed channel repository, a
// real token cipher, and an egress guard that allow-lists loopback so an
// httptest server (127.0.0.1) is a reachable channel target.
func newTestNotifier(t *testing.T) (*Notifier, sqlmock.Sqlmock, *crypto.TokenCipher) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := NewChannelRepository(db)
	tc, err := crypto.NewTokenCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	return NewNotifier(repo, nil, tc, httpsafe.MustGuard("127.0.0.1"), testOpts), mock, tc
}

func webhookChannelRow(id, enc string) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows(notifyChannelCols).AddRow(
		id, "ops", "webhook", enc, []byte(`["test_event"]`), true,
		nil, nil, nil, now, now)
}

func TestNotifier_NilIsNoOp(t *testing.T) {
	var n *Notifier
	n.Notify(context.Background(), Event{Type: testEventType}) // must not panic
	if err := n.SendTest(context.Background(), testChannelID1); err == nil {
		t.Error("SendTest on a nil Notifier should return an error")
	}
}

func TestParseRecipients(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    int
		wantErr bool
	}{
		{"single", "ops@example.com", 1, false},
		{"multiple with spaces", "a@example.com, b@example.com ", 2, false},
		{"skips blanks", "a@example.com,,", 1, false},
		{"empty", "", 0, true},
		{"only blanks", " , ", 0, true},
		{"invalid", "not-an-email", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRecipients(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseRecipients(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if err == nil && len(got) != tc.want {
				t.Errorf("ParseRecipients(%q) = %d recipients, want %d", tc.in, len(got), tc.want)
			}
		})
	}
}

func TestTeamsPayload(t *testing.T) {
	p := teamsPayload("Title", "Body")
	if p["type"] != "message" {
		t.Errorf("type = %v, want message", p["type"])
	}
	if _, ok := p["attachments"]; !ok {
		t.Error("teams payload missing attachments")
	}
}

func TestNotifier_send(t *testing.T) {
	n, _, _ := newTestNotifier(t)
	for _, typ := range []string{"webhook", "slack", "teams"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		if err := n.send(context.Background(), typ, srv.URL, "Title", "Message"); err != nil {
			t.Errorf("send(%s): unexpected error %v", typ, err)
		}
		srv.Close()
	}
}

func TestNotifier_send_Non2xx(t *testing.T) {
	n, _, _ := newTestNotifier(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := n.send(context.Background(), "webhook", srv.URL, "t", "m"); err == nil {
		t.Error("expected an error for a non-2xx destination response")
	}
}

func TestNotifier_send_TransportErrorRedacted(t *testing.T) {
	n, _, _ := newTestNotifier(t)
	// Loopback is allow-listed by the test guard, so the request is attempted
	// and fails to connect (port 1). The error must not embed the target URL.
	target := "http://127.0.0.1:1/secret-webhook-token"
	err := n.send(context.Background(), "webhook", target, "t", "m")
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if got := err.Error(); contains(got, "secret-webhook-token") {
		t.Errorf("send error leaked the target URL: %q", got)
	}
}

func TestNotifier_decryptTarget(t *testing.T) {
	n, _, tc := newTestNotifier(t)
	enc, err := tc.Seal("https://hooks.example.com/x")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := n.decryptTarget(&NotificationChannel{EncryptedTarget: enc})
	if err != nil || got != "https://hooks.example.com/x" {
		t.Fatalf("decryptTarget = (%q, %v)", got, err)
	}
	if _, err := n.decryptTarget(&NotificationChannel{EncryptedTarget: ""}); err == nil {
		t.Error("decryptTarget with no target should error")
	}
	if _, err := n.decryptTarget(&NotificationChannel{EncryptedTarget: "not-valid-ciphertext"}); err == nil {
		t.Error("decryptTarget with a bad ciphertext should error")
	}
}

func TestNotifier_sendEmail_InvalidRecipients(t *testing.T) {
	n, _, _ := newTestNotifier(t)
	// ParseRecipients fails before the (nil-Host) smtp relay is touched.
	if err := n.sendEmail(context.Background(), "not-an-email", "t", "m"); err == nil {
		t.Error("sendEmail with an invalid recipient should error")
	}
}

func TestNotifier_sendEmail_NoSMTPConfigured(t *testing.T) {
	n, _, _ := newTestNotifier(t)
	if err := n.sendEmail(context.Background(), "ops@example.com", "t", "m"); err == nil {
		t.Error("sendEmail with no smtp host configured should error")
	}
}

func TestNotifier_Notify_DeliversToChannel(t *testing.T) {
	hit := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case hit <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n, mock, tc := newTestNotifier(t)
	enc, err := tc.Seal(srv.URL)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	mock.ExpectQuery("WHERE enabled").WillReturnRows(webhookChannelRow(testChannelID1, enc))
	mock.ExpectExec("UPDATE notification_channels SET last_status").WillReturnResult(sqlmock.NewResult(0, 1))

	n.Notify(context.Background(), Event{Type: testEventType, Title: "t", Message: "m"})
	select {
	case <-hit:
	default:
		t.Error("expected the webhook endpoint to receive the notification")
	}
}

func TestNotifier_Notify_RepoError(t *testing.T) {
	n, mock, _ := newTestNotifier(t)
	mock.ExpectQuery("WHERE enabled").WillReturnError(sql.ErrConnDone)
	// A repository failure is logged, not panicked or propagated.
	n.Notify(context.Background(), Event{Type: testEventType})
}

func TestNotifier_Notify_DecryptError(t *testing.T) {
	n, mock, _ := newTestNotifier(t)
	// An undecryptable target makes delivery fail; the failure must be recorded
	// (exercises deliver's error path and record's "failed" branch).
	mock.ExpectQuery("WHERE enabled").WillReturnRows(webhookChannelRow(testChannelID1, "not-decryptable"))
	mock.ExpectExec("UPDATE notification_channels SET last_status").WillReturnResult(sqlmock.NewResult(0, 1))
	n.Notify(context.Background(), Event{Type: testEventType, Title: "t", Message: "m"})
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestNotifier_SendTest_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n, mock, tc := newTestNotifier(t)
	enc, err := tc.Seal(srv.URL)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	mock.ExpectQuery("FROM notification_channels WHERE id").WillReturnRows(webhookChannelRow(testChannelID2, enc))
	mock.ExpectExec("UPDATE notification_channels SET last_status").WillReturnResult(sqlmock.NewResult(0, 1))

	if err := n.SendTest(context.Background(), testChannelID2); err != nil {
		t.Fatalf("SendTest: %v", err)
	}
}

func TestNotifier_SendTest_NotFound(t *testing.T) {
	n, mock, _ := newTestNotifier(t)
	mock.ExpectQuery("FROM notification_channels WHERE id").WillReturnError(sql.ErrNoRows)
	if err := n.SendTest(context.Background(), testChannelID1); err == nil {
		t.Error("SendTest for a missing channel should return an error")
	}
}

func TestNotifier_SendTestEmail_NilIsError(t *testing.T) {
	var n *Notifier
	if err := n.SendTestEmail(context.Background(), []string{"ops@example.com"}, "t", "m"); err == nil {
		t.Error("SendTestEmail on a nil Notifier should return an error")
	}
}

func TestNotifier_SendTestEmail_InvalidRecipients(t *testing.T) {
	n, _, _ := newTestNotifier(t)
	if err := n.SendTestEmail(context.Background(), []string{"not-an-email"}, "t", "m"); err == nil {
		t.Error("SendTestEmail with an invalid recipient should error")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// #153 — the channel target is now bound to its channel row. decryptTarget must
// accept both forms during the transition, and must NOT accept a target bound to
// a different channel.
func TestNotifier_decryptTarget_AcceptsBoundAndLegacyForms(t *testing.T) {
	n, _, tc := newTestNotifier(t)

	legacy, err := tc.Seal("https://hooks.example.com/legacy")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	bound, err := tc.SealWithContext("https://hooks.example.com/bound", TargetContext("chan-1"))
	if err != nil {
		t.Fatalf("SealWithContext: %v", err)
	}

	// A row not yet converted still delivers.
	got, err := n.decryptTarget(&NotificationChannel{ID: "chan-1", EncryptedTarget: legacy})
	if err != nil || got != "https://hooks.example.com/legacy" {
		t.Fatalf("legacy target = (%q, %v); unconverted rows must keep delivering", got, err)
	}

	// A converted row delivers.
	got, err = n.decryptTarget(&NotificationChannel{ID: "chan-1", EncryptedTarget: bound})
	if err != nil || got != "https://hooks.example.com/bound" {
		t.Fatalf("bound target = (%q, %v)", got, err)
	}
}

// The attack the binding exists to stop: copy a sealed target out of one channel
// row and into another. Under the legacy scheme this delivered happily.
func TestNotifier_decryptTarget_RejectsATargetBoundToAnotherChannel(t *testing.T) {
	n, _, tc := newTestNotifier(t)

	sealed, err := tc.SealWithContext("https://hooks.example.com/victim", TargetContext("chan-1"))
	if err != nil {
		t.Fatalf("SealWithContext: %v", err)
	}

	if _, err := n.decryptTarget(&NotificationChannel{ID: "chan-2", EncryptedTarget: sealed}); err == nil {
		t.Fatal("a target moved from chan-1 to chan-2 decrypted; the row binding is not enforced")
	}
}

// TargetContext is the single definition both halves use -- the host seals with
// it, this package opens with it. Pinning the format is the point: a change here
// silently breaks every already-bound ciphertext at delivery time.
func TestTargetContext_IsRowScopedAndStable(t *testing.T) {
	if got := string(TargetContext("chan-1")); got != "identity/notify:notification_channel:chan-1:encrypted_target" {
		t.Errorf("TargetContext(chan-1) = %q; changing this format breaks every stored bound target", got)
	}
	if string(TargetContext("a")) == string(TargetContext("b")) {
		t.Error("TargetContext is not row-scoped; every channel would share one context and the binding would be vacuous")
	}
}
