// Package clean is guard_test.go's fixture for a repository that cannot express
// a privileged mutation without also expressing its audit record.
//
// It lives under testdata so the go tool does not build it; it exists to be
// PARSED.
package clean

import (
	"context"
	"database/sql"
)

// IntentWriter is the app-side spelling of the contract.
type IntentWriter func(ctx context.Context, tx *sql.Tx) error

const grantSQL = `INSERT INTO platform_admins (user_id, granted_by) VALUES ($1, $2)`

type Repo struct{ db *sql.DB }

// Grant takes the writer, so the audit intent is written in the mutation's own
// transaction.
func (r *Repo) Grant(ctx context.Context, userID string, writeIntent IntentWriter) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, grantSQL, userID, nil); err != nil {
		return err
	}
	if err := writeIntent(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Revoke does the same for the delete side.
func (r *Repo) Revoke(ctx context.Context, userID string, writeIntent IntentWriter) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM platform_admins WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if err := writeIntent(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// List reads the table and is not a mutation, so it needs no writer.
func (r *Repo) List(ctx context.Context) (*sql.Rows, error) {
	return r.db.QueryContext(ctx, `SELECT user_id FROM platform_admins ORDER BY granted_at`)
}
