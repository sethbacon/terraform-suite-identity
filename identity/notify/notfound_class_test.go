// notfound_class_test.go is the notify-package half of the "not-found is
// indistinguishable from success" class test (issues #67 and #155). Its store
// counterpart is identity/store/notfound_class_test.go; the two exist
// separately only because ChannelRepository lives in this package, and they
// assert the same contract against the same sentinel — store.ErrNotFound.
//
// notification_channels is administered from an app's admin UI, so every
// accessor here is one an operator reads an outcome from: "channel deleted",
// "channel updated", "last delivery: sent". Each of those was reportable for a
// statement that matched no row before v0.24.0.
package notify

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/sethbacon/terraform-suite-identity/identity/store"
)

// channelAxis is one ChannelRepository accessor that can miss. primeHit and
// primeMiss install the same statement and differ only in whether it matches.
type channelAxis struct {
	name      string
	primeHit  func(mock sqlmock.Sqlmock)
	primeMiss func(mock sqlmock.Sqlmock)
	call      func(r *ChannelRepository) error
}

func channelAxes() []channelAxis {
	id := testChannelID1
	return []channelAxis{
		{
			name: "ChannelRepository.GetByID",
			primeHit: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("FROM notification_channels WHERE id").WillReturnRows(fullChannelRow(id, "ENC"))
			},
			primeMiss: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("FROM notification_channels WHERE id").WillReturnError(sql.ErrNoRows)
			},
			call: func(r *ChannelRepository) error {
				_, err := r.GetByID(context.Background(), id)
				return err
			},
		},
		{
			name: "ChannelRepository.Update",
			primeHit: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("UPDATE notification_channels").WillReturnRows(fullChannelRow(id, "ENC"))
			},
			primeMiss: func(m sqlmock.Sqlmock) { m.ExpectQuery("UPDATE notification_channels").WillReturnError(sql.ErrNoRows) },
			call: func(r *ChannelRepository) error {
				_, err := r.Update(context.Background(), id, "ops", "webhook", nil, true, "E")
				return err
			},
		},
		{
			name: "ChannelRepository.Delete",
			primeHit: func(m sqlmock.Sqlmock) {
				m.ExpectExec("DELETE FROM notification_channels").WillReturnResult(sqlmock.NewResult(0, 1))
			},
			primeMiss: func(m sqlmock.Sqlmock) {
				m.ExpectExec("DELETE FROM notification_channels").WillReturnResult(sqlmock.NewResult(0, 0))
			},
			call: func(r *ChannelRepository) error { return r.Delete(context.Background(), id) },
		},
		{
			name: "ChannelRepository.RecordDelivery",
			primeHit: func(m sqlmock.Sqlmock) {
				m.ExpectExec("UPDATE notification_channels SET last_status").WillReturnResult(sqlmock.NewResult(0, 1))
			},
			primeMiss: func(m sqlmock.Sqlmock) {
				m.ExpectExec("UPDATE notification_channels SET last_status").WillReturnResult(sqlmock.NewResult(0, 0))
			},
			call: func(r *ChannelRepository) error {
				return r.RecordDelivery(context.Background(), id, "sent", "", time.Now())
			},
		},
	}
}

// TestNotFoundClass_ChannelMissReportsStoreSentinel pins that this package
// reports a miss with the SAME sentinel identity/store uses. A second,
// notify-local sentinel would be worse than none: a consuming app wires both
// packages and would have to know which spelling each repository speaks.
func TestNotFoundClass_ChannelMissReportsStoreSentinel(t *testing.T) {
	for _, axis := range channelAxes() {
		t.Run(axis.name, func(t *testing.T) {
			repo, mock := newChannelRepo(t)
			axis.primeMiss(mock)

			err := axis.call(repo)
			if !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("%s: a miss returned err=%v, want an error wrapping store.ErrNotFound",
					axis.name, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: %v", axis.name, err)
			}
		})
	}
}

// TestNotFoundClass_ChannelHitStillSucceeds is the other direction, without
// which an accessor that always errored would satisfy the table above.
func TestNotFoundClass_ChannelHitStillSucceeds(t *testing.T) {
	for _, axis := range channelAxes() {
		t.Run(axis.name, func(t *testing.T) {
			repo, mock := newChannelRepo(t)
			axis.primeHit(mock)

			if err := axis.call(repo); err != nil {
				t.Fatalf("%s: a hit returned err=%v, want nil", axis.name, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: %v", axis.name, err)
			}
		})
	}
}
