package store

import "strings"

// escapeLikePattern escapes the LIKE/ILIKE wildcard metacharacters (%, _) and
// the escape character itself (\) in a user-supplied search term so they match
// literally instead of being interpreted as patterns. Without this, a term such
// as "50%" or "a_b" widens the match (pattern injection) and a term of many
// wildcards can force an expensive scan (ReDoS-style DoS).
//
// Postgres uses backslash as LIKE's default escape character, and the escaped
// value is passed as a bound parameter (data, not a SQL string literal), so it
// is unaffected by standard_conforming_strings and needs no ESCAPE clause.
// Callers still wrap the result in %...% for a substring match.
func escapeLikePattern(s string) string {
	// Backslash MUST be escaped first; NewReplacer does a single left-to-right
	// pass without re-scanning its own output, so the ordering here is safe.
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
