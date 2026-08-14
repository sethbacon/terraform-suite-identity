// Package unaudited_literal is guard_test.go's fixture for the case registry's
// original scan already caught: SQL written as a literal inside the function
// body, with no audit-intent writer in the signature.
package unaudited_literal

import (
	"context"
	"database/sql"
)

// IntentWriter is declared so the fixture differs from `clean` only in which
// functions take one.
type IntentWriter func(ctx context.Context, tx *sql.Tx) error

type Repo struct{ db *sql.DB }

// Grant is audited.
func (r *Repo) Grant(ctx context.Context, userID string, writeIntent IntentWriter) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO platform_admins (user_id) VALUES ($1)`, userID); err != nil {
		return err
	}
	if err := writeIntent(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// PurgeAdmin is the helper nobody wrote a behavioural test for.
func (r *Repo) PurgeAdmin(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM platform_admins WHERE user_id = $1`, userID)
	return err
}
