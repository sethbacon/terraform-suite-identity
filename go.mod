module github.com/sethbacon/terraform-suite-identity

go 1.25.0

// Pinned to a patched release (CVE-2026-42505 / GO-2026-5856, a crypto/tls ECH
// privacy leak affecting Go before 1.25.12 and the 1.26.x line before 1.26.5).
// go command and CI (actions/setup-go with go-version-file) both honor this
// directive and auto-select/install it.
toolchain go1.26.5

require (
	github.com/DATA-DOG/go-sqlmock v1.5.2
	github.com/coreos/go-oidc/v3 v3.20.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/golang-migrate/migrate/v4 v4.19.1
	github.com/google/uuid v1.6.0
	github.com/jmoiron/sqlx v1.4.0
	github.com/lib/pq v1.12.3
	golang.org/x/crypto v0.54.0
	golang.org/x/net v0.57.0
	golang.org/x/oauth2 v0.36.0
)

require (
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	golang.org/x/text v0.40.0 // indirect
)
