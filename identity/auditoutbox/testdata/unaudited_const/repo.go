// Package unaudited_const is the case registry's original scan MISSED.
//
// The SQL is hoisted into a package-level constant — the same idiom
// terraform-registry-backend's own audit/outbox.go uses for its INSERT — and
// assembled by concatenation. A scan that only reads string literals appearing
// inside the function body sees nothing here and reports green.
package unaudited_const

import (
	"context"
	"database/sql"
)

// IntentWriter is declared so a scan cannot pass merely because the type is
// absent from the package.
type IntentWriter func(ctx context.Context, tx *sql.Tx) error

const (
	carrierTable = "platform_admins"
	// Built from another constant, so resolving one name is not enough.
	revokeSQL = `DELETE FROM ` + carrierTable + ` WHERE user_id = $1`
)

// grantSQL is a package-level VAR rather than a const, because "var" is where
// SQL ends up as soon as anyone builds it with fmt.Sprintf's cousin.
var grantSQL = `INSERT INTO ` + carrierTable + ` (user_id) VALUES ($1)`

type Repo struct{ db *sql.DB }

// Grant is unaudited and invisible to a body-literals-only scan.
func (r *Repo) Grant(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, grantSQL, userID)
	return err
}

// Revoke is unaudited too.
func (r *Repo) Revoke(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, revokeSQL, userID)
	return err
}

// Audited is the control: same const, but the signature carries the contract.
func (r *Repo) Audited(ctx context.Context, userID string, writeIntent IntentWriter) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, grantSQL, userID); err != nil {
		return err
	}
	if err := writeIntent(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}
