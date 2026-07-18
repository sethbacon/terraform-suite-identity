package notify

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

var errDB = errors.New("db error")

func newChannelRepo(t *testing.T) (*ChannelRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewChannelRepository(db), mock
}

var channelTestCols = []string{
	"id", "name", "type", "encrypted_target", "events", "enabled",
	"last_status", "last_error", "last_sent_at", "created_at", "updated_at",
}

// fullChannelRow populates every nullable column and a non-empty events array,
// exercising the JSON unmarshal and the Valid branches of scanChannel.
func fullChannelRow(id, enc string) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows(channelTestCols).AddRow(
		id, "ops-webhook", "webhook", enc, []byte(`["cve_detected"]`), true,
		"sent", "prior failure", now, now, now)
}

// minimalChannelRow uses NULL status/error/sent_at and NULL events, exercising
// the empty-events and nil-NullX branches of scanChannel.
func minimalChannelRow(id, enc string) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows(channelTestCols).AddRow(
		id, "ops-mail", "email", enc, nil, true,
		nil, nil, nil, now, now)
}

func TestChannelRepo_Create(t *testing.T) {
	repo, mock := newChannelRepo(t)
	id := testChannelID1
	mock.ExpectQuery("INSERT INTO notification_channels").
		WillReturnRows(fullChannelRow(id, "ENC"))

	ch := &NotificationChannel{Name: "ops-webhook", Type: "webhook", EncryptedTarget: "ENC", Events: []string{"cve_detected"}, Enabled: true}
	saved, err := repo.Create(context.Background(), ch)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if saved.ID != id {
		t.Errorf("ID = %v, want %v", saved.ID, id)
	}
	if saved.EncryptedTarget != "" {
		t.Error("Create must redact EncryptedTarget in the returned channel")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestChannelRepo_Create_DBError(t *testing.T) {
	repo, mock := newChannelRepo(t)
	mock.ExpectQuery("INSERT INTO notification_channels").WillReturnError(errDB)
	if _, err := repo.Create(context.Background(), &NotificationChannel{Events: []string{}}); err == nil {
		t.Error("expected error")
	}
}

func TestChannelRepo_List(t *testing.T) {
	repo, mock := newChannelRepo(t)
	id := testChannelID1
	mock.ExpectQuery("FROM notification_channels ORDER BY created_at DESC").
		WillReturnRows(fullChannelRow(id, "ENC"))
	list, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("len = %d, want 1", len(list))
	}
	if list[0].EncryptedTarget != "" {
		t.Error("List must redact EncryptedTarget")
	}
	if list[0].LastStatus == nil || *list[0].LastStatus != "sent" {
		t.Error("expected LastStatus 'sent'")
	}
}

func TestChannelRepo_List_DBError(t *testing.T) {
	repo, mock := newChannelRepo(t)
	mock.ExpectQuery("FROM notification_channels ORDER BY").WillReturnError(errDB)
	if _, err := repo.List(context.Background()); err == nil {
		t.Error("expected error")
	}
}

func TestChannelRepo_GetByID(t *testing.T) {
	repo, mock := newChannelRepo(t)
	id := testChannelID1
	mock.ExpectQuery("FROM notification_channels WHERE id").
		WillReturnRows(minimalChannelRow(id, "ENC"))
	ch, err := repo.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if ch == nil || ch.ID != id {
		t.Fatalf("GetByID returned %+v", ch)
	}
	if len(ch.Events) != 0 {
		t.Errorf("expected empty events, got %v", ch.Events)
	}
	if ch.EncryptedTarget != "ENC" {
		t.Error("GetByID must return the encrypted target for decryption")
	}
}

func TestChannelRepo_GetByID_NotFound(t *testing.T) {
	repo, mock := newChannelRepo(t)
	mock.ExpectQuery("FROM notification_channels WHERE id").WillReturnError(sql.ErrNoRows)
	ch, err := repo.GetByID(context.Background(), testChannelID1)
	if err != nil || ch != nil {
		t.Errorf("GetByID(no rows) = (%v, %v), want (nil, nil)", ch, err)
	}
}

func TestChannelRepo_GetByID_DBError(t *testing.T) {
	repo, mock := newChannelRepo(t)
	mock.ExpectQuery("FROM notification_channels WHERE id").WillReturnError(errDB)
	if _, err := repo.GetByID(context.Background(), testChannelID1); err == nil {
		t.Error("expected error")
	}
}

func TestChannelRepo_GetByID_BadEventsJSON(t *testing.T) {
	repo, mock := newChannelRepo(t)
	id := testChannelID1
	now := time.Now()
	rows := sqlmock.NewRows(channelTestCols).AddRow(
		id, "x", "webhook", "ENC", []byte("{not-json"), true,
		nil, nil, nil, now, now)
	mock.ExpectQuery("FROM notification_channels WHERE id").WillReturnRows(rows)
	if _, err := repo.GetByID(context.Background(), id); err == nil {
		t.Error("expected JSON unmarshal error")
	}
}

func TestChannelRepo_Update(t *testing.T) {
	repo, mock := newChannelRepo(t)
	id := testChannelID1
	mock.ExpectQuery("UPDATE notification_channels").
		WillReturnRows(fullChannelRow(id, "ENC"))
	updated, err := repo.Update(context.Background(), id, "ops", "webhook", []string{"cve_detected"}, true, "NEWENC")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated == nil || updated.EncryptedTarget != "" {
		t.Error("Update must return a redacted channel")
	}
}

func TestChannelRepo_Update_KeepTarget(t *testing.T) {
	repo, mock := newChannelRepo(t)
	id := testChannelID1
	mock.ExpectQuery("UPDATE notification_channels").
		WillReturnRows(minimalChannelRow(id, "ENC"))
	// Empty encryptedTarget => COALESCE keeps the existing one.
	if _, err := repo.Update(context.Background(), id, "ops", "email", nil, false, ""); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

func TestChannelRepo_Update_NotFound(t *testing.T) {
	repo, mock := newChannelRepo(t)
	mock.ExpectQuery("UPDATE notification_channels").WillReturnError(sql.ErrNoRows)
	ch, err := repo.Update(context.Background(), testChannelID1, "n", "webhook", nil, true, "E")
	if err != nil || ch != nil {
		t.Errorf("Update(no rows) = (%v, %v), want (nil, nil)", ch, err)
	}
}

func TestChannelRepo_Update_DBError(t *testing.T) {
	repo, mock := newChannelRepo(t)
	mock.ExpectQuery("UPDATE notification_channels").WillReturnError(errDB)
	if _, err := repo.Update(context.Background(), testChannelID1, "n", "webhook", nil, true, "E"); err == nil {
		t.Error("expected error")
	}
}

func TestChannelRepo_Delete(t *testing.T) {
	repo, mock := newChannelRepo(t)
	mock.ExpectExec("DELETE FROM notification_channels").WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repo.Delete(context.Background(), testChannelID1); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestChannelRepo_Delete_DBError(t *testing.T) {
	repo, mock := newChannelRepo(t)
	mock.ExpectExec("DELETE FROM notification_channels").WillReturnError(errDB)
	if err := repo.Delete(context.Background(), testChannelID1); err == nil {
		t.Error("expected error")
	}
}

func TestChannelRepo_ListEnabledForEvent(t *testing.T) {
	repo, mock := newChannelRepo(t)
	id := testChannelID1
	mock.ExpectQuery("WHERE enabled").WillReturnRows(fullChannelRow(id, "ENC"))
	list, err := repo.ListEnabledForEvent(context.Background(), "cve_detected")
	if err != nil {
		t.Fatalf("ListEnabledForEvent: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("len = %d, want 1", len(list))
	}
	// The encrypted target must be retained here (it is needed to send).
	if list[0].EncryptedTarget != "ENC" {
		t.Error("ListEnabledForEvent must retain the encrypted target")
	}
}

func TestChannelRepo_ListEnabledForEvent_DBError(t *testing.T) {
	repo, mock := newChannelRepo(t)
	mock.ExpectQuery("WHERE enabled").WillReturnError(errDB)
	if _, err := repo.ListEnabledForEvent(context.Background(), "cve_detected"); err == nil {
		t.Error("expected error")
	}
}

func TestChannelRepo_RecordDelivery(t *testing.T) {
	repo, mock := newChannelRepo(t)
	mock.ExpectExec("UPDATE notification_channels SET last_status").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repo.RecordDelivery(context.Background(), testChannelID1, "sent", "", time.Now()); err != nil {
		t.Fatalf("RecordDelivery: %v", err)
	}
}

func TestChannelRepo_RecordDelivery_DBError(t *testing.T) {
	repo, mock := newChannelRepo(t)
	mock.ExpectExec("UPDATE notification_channels SET last_status").WillReturnError(errDB)
	if err := repo.RecordDelivery(context.Background(), testChannelID1, "failed", "boom", time.Now()); err == nil {
		t.Error("expected error")
	}
}
