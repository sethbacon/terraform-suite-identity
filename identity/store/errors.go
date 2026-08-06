package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// ErrNotFound reports that an accessor matched no row.
//
// It is the module's SINGLE not-found sentinel: every read that can miss and
// every by-identifier mutation that can match zero rows reports it, wrapped, so
// `errors.Is(err, store.ErrNotFound)` is the one check a caller needs. Do not
// introduce a second one — a package with two not-found sentinels has none,
// because a caller cannot know which to test for.
//
// # Why this exists
//
// Until v0.24.0 a read that found nothing returned (nil, nil) and a by-id
// UPDATE/DELETE that matched nothing returned nil. Both are the same defect
// wearing two hats: the accessor had NO WAY to tell its caller that nothing
// matched, so "I did the work" and "there was nothing to do" arrived over the
// same wire.
//
// On the read side that shape is a nil-dereference trap — the idiomatic
// `x, err := Get(...); if err != nil { return err }; use(x.Field)` panics on a
// miss instead of denying the request. On the write side it is worse: a
// revocation, a member removal, a role change or an organization delete that
// matched zero rows reported success, and the consuming app's UI and audit log
// both recorded a security-state change that never happened.
//
// It is also a precondition for tenancy enforcement. A write carrying a tenant
// predicate that matches no row means "that row is not yours"; without a
// distinguishable zero-row result, adding the predicate would FAIL OPEN — the
// caller would be told the write succeeded precisely when the guard stopped it.
//
// # What does NOT return it
//
//   - List/Search accessors. An empty result set is a legitimate answer to
//     "which rows match?", not a miss; they return an empty slice and nil.
//   - Bulk mutations (DeleteExpiredKeys, RemoveAllMembershipsForUser,
//     DeactivateAllOIDCConfigs, CleanupExpiredRevocations,
//     DeleteAuditLogsBefore). Zero rows is a normal outcome for a sweep, so
//     they report the affected COUNT instead — distinguishable without being an
//     error.
//   - Predicates that already have a way to say "no" in band:
//     CheckMembership returns (false, nil, nil) and GetUserScopesForOrg returns
//     an empty scope set. Both absorb ErrNotFound deliberately; see their docs.
//   - Inserts, including RevokeToken's ON CONFLICT DO NOTHING, where zero rows
//     affected means "already present" — an idempotent success, not a miss.
var ErrNotFound = errors.New("store: not found")

// notFound wraps ErrNotFound with the accessor's own context.
//
// what names the ENTITY AND LOOKUP AXIS ("api key by hash"), never the
// identifier value: the caller already holds the value it passed, and some of
// these axes key on material that must not reach a log line (GetAPIKeyByHash's
// argument is a credential digest).
func notFound(what string) error {
	return fmt.Errorf("%s: %w", what, ErrNotFound)
}

// requireRow turns a by-identifier mutation's sql.Result into ErrNotFound when
// it matched no row.
//
// Every by-id UPDATE/DELETE in this package routes its result through here
// rather than reading RowsAffected inline, so "did anyone check?" is answerable
// by grep and a new mutator that forgets is visibly different from its
// neighbours.
func requireRow(res sql.Result, what string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to read rows affected for %s: %w", what, err)
	}
	if n == 0 {
		return notFound(what)
	}
	return nil
}

// affectedRows reports how many rows a BULK mutation touched.
//
// Bulk sweeps use this instead of requireRow because zero is a correct,
// unremarkable answer for them ("no expired keys today"); the caller still gets
// a distinguishable result, just as a count rather than an error. It mirrors
// DeleteAuditLogsBefore, which already reported its count before this batch.
func affectedRows(res sql.Result, what string) (int64, error) {
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to read rows affected for %s: %w", what, err)
	}
	return n, nil
}
