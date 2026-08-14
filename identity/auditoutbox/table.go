// table.go is the parameterisation this package exists to add.
//
// The mechanism it ships was built in terraform-registry-backend against two
// hardcoded names: `audit_outbox` and `audit_logs`. Under the identity model
// (issue #206) audit_logs is PER-APP — each app records the actions taken in
// it, in its own schema — so a shared implementation cannot name either table.
// Every statement here therefore addresses a table the consuming app supplied.
//
// A table name is the one part of a SQL statement that cannot be a bind
// parameter, so it is interpolated, so it is validated. The accepted grammar is
// deliberately narrower than PostgreSQL's:
//
//	[schema.]table, each part matching ^[a-z_][a-z0-9_$]*$, at most 63 bytes
//
// Lowercase only, and no quoted identifiers. That is not laziness about
// escaping — every name is still quoted before it reaches SQL. It is about
// FOLDING: PostgreSQL folds an unquoted `Audit_Outbox` to `audit_outbox`, but a
// quoted "Audit_Outbox" is a different, case-sensitive table. A package that
// accepted mixed case would have to guess which of the two the operator meant,
// and would silently address the wrong one when it guessed wrong. Rejecting the
// ambiguity is the only answer that cannot be wrong quietly.
package auditoutbox

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/lib/pq"
)

// ErrInvalidTable is the sentinel every table-name rejection wraps. A caller
// that mistypes a name finds out at construction, not at the first privileged
// mutation.
var ErrInvalidTable = errors.New("identity/auditoutbox: invalid table name")

// maxIdentifierLength is PostgreSQL's NAMEDATALEN-1. An identifier longer than
// this is TRUNCATED rather than rejected by the server, which is how two
// distinct generated names silently become one object.
const maxIdentifierLength = 63

var identifierPattern = regexp.MustCompile(`^[a-z_][a-z0-9_$]*$`)

// table is a validated, optionally schema-qualified table identifier.
//
// Unexported: the constructors take strings and validate, so a consumer has one
// way to name a table and one place where a bad name is refused.
type table struct {
	schema string // "" when the name was given unqualified
	name   string
}

// parseTable validates s and returns it. what names the argument in the error
// ("outbox table", "destination table"), because a message that does not say
// WHICH of the two names was wrong makes the operator try both.
func parseTable(what, s string) (table, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return table{}, fmt.Errorf("%w: %s is empty; this package names no table of its own, "+
			"the consuming app supplies it", ErrInvalidTable, what)
	}

	parts := strings.Split(trimmed, ".")
	if len(parts) > 2 {
		return table{}, fmt.Errorf("%w: %s %q has %d dot-separated parts, want at most 2 (schema.table)",
			ErrInvalidTable, what, s, len(parts))
	}

	for _, part := range parts {
		if err := validateIdentifier(what, s, part); err != nil {
			return table{}, err
		}
	}

	if len(parts) == 2 {
		return table{schema: parts[0], name: parts[1]}, nil
	}
	return table{name: parts[0]}, nil
}

func validateIdentifier(what, whole, part string) error {
	if len(part) > maxIdentifierLength {
		return fmt.Errorf("%w: %s %q contains a %d-byte identifier %q; PostgreSQL truncates at %d, "+
			"which would silently address a different object", ErrInvalidTable, what, whole, len(part), part, maxIdentifierLength)
	}
	if identifierPattern.MatchString(part) {
		return nil
	}
	// The case-specific message only when case is the ONLY problem: a name that
	// is also malformed is not a folding question, and saying so would send the
	// operator to lowercase something that still would not parse.
	if lowered := strings.ToLower(part); lowered != part && identifierPattern.MatchString(lowered) {
		return fmt.Errorf("%w: %s %q contains upper case in %q. Unquoted identifiers fold to lower "+
			"case and quoted ones do not, so a mixed-case name means two different tables; "+
			"name the folded (lower-case) table", ErrInvalidTable, what, whole, part)
	}
	return fmt.Errorf("%w: %s %q contains %q, which is not [a-z_][a-z0-9_$]*", ErrInvalidTable, what, whole, part)
}

// String returns the name as the caller wrote it, for logs and errors.
func (t table) String() string {
	if t.schema == "" {
		return t.name
	}
	return t.schema + "." + t.name
}

// sql returns the quoted form to interpolate into a statement. Quoting is
// redundant against the accepted grammar and applied anyway: it is what keeps a
// table legitimately named `user` or `order` from parsing as a keyword.
func (t table) sql() string {
	if t.schema == "" {
		return pq.QuoteIdentifier(t.name)
	}
	return pq.QuoteIdentifier(t.schema) + "." + pq.QuoteIdentifier(t.name)
}

// derive returns a sibling object name in this table's schema — the generated
// function and trigger names in ddl.go.
//
// The length check is the point. A 60-character outbox table plus
// "_assert_intent" is a 74-byte identifier, which PostgreSQL accepts, truncates,
// and then happily lets a second generated name collide with. Refusing is the
// only way that is visible.
func (t table) derive(suffix string) (table, error) {
	name := t.name + suffix
	if len(name) > maxIdentifierLength {
		return table{}, fmt.Errorf("%w: the generated name %q is %d bytes; PostgreSQL truncates at %d, "+
			"so two generated objects could collide. Shorten the table name",
			ErrInvalidTable, name, len(name), maxIdentifierLength)
	}
	return table{schema: t.schema, name: name}, nil
}
