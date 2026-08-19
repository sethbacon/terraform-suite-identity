// Package pgquote quotes identifiers and literals for SQL this module builds as
// text rather than sends as parameters.
//
// # Why this exists
//
// Almost every query here is parameterised, which is the only quoting that
// belongs on a data path. Two things cannot be: DDL, because PostgreSQL does
// not accept bind parameters in a CREATE FUNCTION body or a CREATE TRIGGER
// (see identity/auditoutbox), and identifiers, which are never parameterisable
// anywhere. Those callers have to interpolate, so they need the escaping rules
// written down in one place instead of open-coded per call site.
//
// # Why it is not just a call into the driver
//
// This module moved off github.com/lib/pq, which exported QuoteIdentifier and
// QuoteLiteral. pgx exports an equivalent for the first and NOTHING for the
// second: its QuoteString lives in internal/sanitize, so it is not importable,
// and it is not equivalent anyway — it doubles single quotes and stops there.
// Literal below therefore carries the rest of the algorithm itself.
package pgquote

import (
	"strings"

	"github.com/jackc/pgx/v5"
)

// Identifier quotes a table, column or function name.
//
// It differs from lib/pq's QuoteIdentifier, which this replaced, on one input:
// given an interior NUL, lib/pq truncated at it and pgx strips it, so "a\x00b"
// was "a" and is now "ab". Both are injection-safe and callers here validate
// names long before this point, so the change is noted rather than compensated
// for.
func Identifier(name string) string {
	return pgx.Identifier{name}.Sanitize()
}

// Literal quotes a string constant for a statement that cannot take a parameter.
//
// This is PostgreSQL's own algorithm, from PQEscapeStringInternal in
// libpq/fe-exec.c: double any single quote, and if the input contains a
// backslash, double those too and switch to the C-style E” form so the
// doubling is read literally under any standard_conforming_strings setting.
// The leading space before E is libpq's and is kept — without it the E can fuse
// with a preceding identifier character and change the token.
//
// Quoting is not by itself a defence in every position. A literal interpolated
// into a -- comment is still bounded by the newline that ends the comment, not
// by these quotes.
func Literal(literal string) string {
	literal = strings.ReplaceAll(literal, `'`, `''`)
	if strings.Contains(literal, `\`) {
		return ` E'` + strings.ReplaceAll(literal, `\`, `\\`) + `'`
	}
	return `'` + literal + `'`
}
