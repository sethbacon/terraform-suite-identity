package pgquote

// identifier.go is the ONE definition of which identifiers this module accepts
// from a consumer (#213).
//
// # Why it is here rather than in each package
//
// Three packages validated a consumer-supplied table name, each with its own
// copy, and the copies had DRIFTED into two different grammars:
//
//	identity/platformadmin   ^[A-Za-z_][A-Za-z0-9_$]*$   mixed case accepted
//	identity/store           ^[A-Za-z_][A-Za-z0-9_$]*$   mixed case accepted
//	identity/auditoutbox     ^[a-z_][a-z0-9_$]*$         mixed case refused
//
// An application that wires a platform-admin carrier AND an audit outbox
// against one database — which both consuming backends now do — must pick a
// name every package accepts. So the effective grammar was already the strict
// one, by intersection, and the permissive branch was unreachable in practice:
// a rule nobody wrote down, arrived at by accident rather than by decision.
//
// identity/store/audit_sweep.go carried the reason the duplication was
// tolerated: "a shared internal helper for two call sites would be a package
// whose only purpose is to be shared." That was a fair call at two. It stopped
// being one at three, and the drift is what it cost.
//
// # Why the strict grammar won
//
// Both arguments were sound. Refusing "MixedCase" makes the package unusable
// against a table an operator genuinely created with quoted DDL. Accepting it
// means an operator who wrote CREATE TABLE MixedCase (...) unquoted actually
// created mixedcase, and quoting their config string then addresses something
// that does not exist.
//
// The tiebreak is which failure is QUIET. PostgreSQL folds an unquoted
// Audit_Outbox to audit_outbox, but a quoted "Audit_Outbox" is a different,
// case-sensitive table. A package accepting mixed case has to guess which the
// operator meant, and addresses the wrong one when it guesses wrong. Usually
// that is loud — the quoted name does not exist and the first query says so —
// but where BOTH tables exist it is silent, and it is silent on a privileged
// mutation surface.
//
// Refusing the ambiguity is the only answer that cannot be wrong quietly, and
// it costs nothing real: every consumer in the estate passes a lowercase name.

import "regexp"

// MaxIdentifierLength is PostgreSQL's NAMEDATALEN-1.
//
// An identifier longer than this is TRUNCATED by the server rather than
// refused, which is how two distinct configured names silently become one
// object — two carriers addressing one table while taking two different
// advisory locks. Refused here rather than truncated.
const MaxIdentifierLength = 63

// identifierPattern is the accepted shape of one identifier part.
//
// Deliberately narrower than PostgreSQL's. A table name is the one part of
// these statements that cannot be a bind parameter, so it is interpolated — and
// it is admitted only in the shape that has no interpretation beyond itself.
// Every name is still quoted before it reaches SQL; this is about ambiguity,
// not escaping.
var identifierPattern = regexp.MustCompile(`^[a-z_][a-z0-9_$]*$`)

// ValidIdentifier reports whether part is an acceptable identifier: lowercase,
// unqualified, and within PostgreSQL's length limit.
//
// Callers keep their own error types and messages — a consumer needs to know
// WHICH name was wrong, and only the caller knows what it was called. What is
// shared is the grammar, which is the thing that drifted.
func ValidIdentifier(part string) bool {
	return len(part) <= MaxIdentifierLength && identifierPattern.MatchString(part)
}
