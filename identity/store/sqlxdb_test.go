package store

import (
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// TestNewSqlxDBUsesThePostgresBindvarDialect pins the driver name handed to
// sqlx.NewDb.
//
// Nothing in this package rebinds today — the two sqlx repositories use
// GetContext/SelectContext/StructScan with `$1` written literally into the SQL,
// none of which consult the dialect — so a wrong name is currently invisible.
// That is exactly why it is asserted here rather than left to be discovered:
// the first `sqlx.In`, `NamedExecContext` or `Rebind` added to this package
// would silently emit `?` placeholders against PostgreSQL, and the failure
// would surface as a syntax error at runtime in a consumer, far from the
// one-word cause.
//
// The wrong name is not hypothetical. Before v0.25.0 these repositories took a
// caller-supplied *sqlx.DB, and every test in both consuming applications built
// it with sqlx.NewDb(db, "sqlmock") — an unregistered name that sqlx maps to
// the QUESTION dialect. The handle is now constructed in one place, so the
// dialect is a property of this package rather than of whatever each caller
// happened to pass.
func TestNewSqlxDBUsesThePostgresBindvarDialect(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	sx := newSqlxDB(db)
	if got := sx.DriverName(); got != "postgres" {
		t.Errorf("DriverName() = %q, want %q", got, "postgres")
	}
	if got := sx.Rebind("SELECT 1 FROM t WHERE a = ? AND b = ?"); got != "SELECT 1 FROM t WHERE a = $1 AND b = $2" {
		t.Errorf("Rebind produced %q; the handle is not using the PostgreSQL "+
			"bindvar dialect, so any named or IN query added to this package would "+
			"emit ?-style placeholders against PostgreSQL", got)
	}
}

// TestNewSqlxDBSharesTheCallersPool pins that adorning the pool does not open a
// second one: the wrapped handle must be backed by the very *sql.DB it was
// given, since this package never owns (and never closes) the caller's pool.
func TestNewSqlxDBSharesTheCallersPool(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if sx := newSqlxDB(db); sx.DB != db {
		t.Error("newSqlxDB did not wrap the caller's *sql.DB; a second pool would " +
			"double the connection budget every consumer sized for one")
	}
}
