// fail_open_class_test.go pins the direction the store's security decisions
// fail in when they cannot answer the question they were asked.
//
// A revocation lookup has an asymmetry that a plain CRUD read does not: the
// answer "no row" is indistinguishable from "I could not look", and both would
// naturally be reported as false — "not revoked" — which admits the token. An
// empty identifier reaches the same place through a different door: it matches
// no row by construction, so a denylist wired against a field that is always
// empty reports every token as clean, forever, with nothing in the logs.
package store

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// TestFailOpenClass_IsTokenRevoked sweeps the revocation check with the inputs
// that cannot be answered alongside the two that can, and pins that only a
// definite "no row" reports the token as usable.
func TestFailOpenClass_IsTokenRevoked(t *testing.T) {
	tests := []struct {
		name string
		jti  string
		// expect wires the sqlmock expectation; nil means the repository must
		// not reach the database at all.
		expect func(mock sqlmock.Sqlmock)
		// wantRevoked is the value a caller acts on. true denies the token.
		wantRevoked bool
		wantErr     error
		wantAnyErr  bool
	}{
		{
			name: "known-good token is usable",
			jti:  "jti-123",
			expect: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs("jti-123").
					WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
			},
			wantRevoked: false,
		},
		{
			name: "revoked token is denied",
			jti:  "jti-123",
			expect: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs("jti-123").
					WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
			},
			wantRevoked: true,
		},
		{
			name:        "empty identifier is refused without a lookup",
			jti:         "",
			wantRevoked: true,
			wantErr:     ErrEmptyTokenID,
		},
		{
			name: "unanswerable lookup denies rather than admits",
			jti:  "jti-123",
			expect: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT EXISTS").WillReturnError(errDB)
			},
			wantRevoked: true,
			wantAnyErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, mock := newTokenRepo(t)
			if tt.expect != nil {
				tt.expect(mock)
			}

			revoked, err := repo.IsTokenRevoked(context.Background(), tt.jti)

			if revoked != tt.wantRevoked {
				t.Errorf("revoked = %v; want %v", revoked, tt.wantRevoked)
			}
			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("error = %v; want %v", err, tt.wantErr)
				}
			case tt.wantAnyErr:
				if err == nil {
					t.Error("error = nil; want the lookup failure surfaced")
				}
			default:
				if err != nil {
					t.Errorf("error = %v; want nil", err)
				}
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("sqlmock expectations: %v", err)
			}
		})
	}
}

// TestFailOpenClass_RevokeToken pins that a revocation which cannot possibly
// take effect is reported as a failure rather than as a success. An empty
// identifier would insert a row no lookup can ever match, so a caller told
// "revoked" would be told something untrue.
func TestFailOpenClass_RevokeToken(t *testing.T) {
	exp := time.Now().Add(time.Hour)

	tests := []struct {
		name    string
		jti     string
		expect  func(mock sqlmock.Sqlmock)
		wantErr error
	}{
		{
			name: "real identifier is recorded",
			jti:  "jti-123",
			expect: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("INSERT INTO revoked_tokens").
					WithArgs("jti-123", "user-456", exp).
					WillReturnResult(sqlmock.NewResult(1, 1))
				// A successful revocation also self-prunes the denylist
				// (see RevokeToken); expected here so the prune's DELETE
				// is not an unexpected call.
				mock.ExpectExec("DELETE FROM revoked_tokens").
					WillReturnResult(sqlmock.NewResult(0, 0))
			},
		},
		{
			name:    "empty identifier is refused without a write",
			jti:     "",
			wantErr: ErrEmptyTokenID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, mock := newTokenRepo(t)
			if tt.expect != nil {
				tt.expect(mock)
			}

			err := repo.RevokeToken(context.Background(), tt.jti, "user-456", exp)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("error = %v; want %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("error = %v; want nil", err)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("sqlmock expectations: %v", err)
			}
		})
	}
}
