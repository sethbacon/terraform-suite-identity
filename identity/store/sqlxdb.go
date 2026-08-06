// sqlxdb.go confines this package's use of jmoiron/sqlx to an implementation
// detail.
//
// Every exported constructor in package store takes the same handle type,
// *sql.DB. Two repositories (RoleTemplateRepository, OIDCConfigRepository)
// genuinely benefit from sqlx's db-tag struct scanning, and they get it by
// adorning the caller's pool here rather than by demanding a different handle
// type at the boundary. Before v0.25.0 those two constructors took a *sqlx.DB,
// which meant a consuming application had to build and inject two handle types
// for one identity layer — terraform-state-manager-backend was calling
// sqlx.NewDb(identityDB, "postgres") inline at two call sites purely to satisfy
// the signature, and terraform-registry-backend threaded a parallel
// identitySqlxDB alongside its *sql.DB. That wrapping now happens once, here.
package store

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
)

// sqlxDriverName is the driver name handed to sqlx.NewDb. It selects the
// bindvar dialect sqlx uses for Rebind and named queries: "postgres" means
// $1, $2, … which is what every query in this package is written with.
//
// sqlx.NewDb does NOT open a connection or consult the driver registry — it
// wraps the *sql.DB it is given — so this name is a formatting choice, not a
// claim about the caller's driver. It is correct for lib/pq and pgx/stdlib
// alike, and (unlike the "sqlmock" name test code used to pass in) it cannot
// silently select the ?-style dialect for a Postgres pool.
const sqlxDriverName = "postgres"

// newSqlxDB adorns an existing *sql.DB with sqlx's struct-scanning helpers.
// It shares the caller's connection pool: no second pool is opened, and
// closing the returned handle is neither required nor performed by this
// package, which never owns the pool it is handed.
func newSqlxDB(db *sql.DB) *sqlx.DB {
	return sqlx.NewDb(db, sqlxDriverName)
}
