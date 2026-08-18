package pgquote

import "testing"

func TestLiteral(t *testing.T) {
	// Golden values are lib/pq's QuoteLiteral output for the same inputs,
	// verified against it directly while it was still a dependency.
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "audit.write", `'audit.write'`},
		{"empty", "", `''`},
		{"single quote", "it's", `'it''s'`},
		{"only a quote", "'", `''''`},
		{"quote at both ends", "'x'", `'''x'''`},
		{"backslash switches to E form", `a\b`, ` E'a\\b'`},
		{"backslash and quote", `a\'b`, ` E'a\\''b'`},
		{"double backslash", `a\\b`, ` E'a\\\\b'`},
		{"newline is not escaped, only quoted", "a\nb", "'a\nb'"},
		{"semicolon is inert inside quotes", "a; DROP TABLE t", `'a; DROP TABLE t'`},
		{"quote-out attempt stays quoted", "'; DROP TABLE t; --", `'''; DROP TABLE t; --'`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Literal(c.in); got != c.want {
				t.Errorf("Literal(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestIdentifier(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "outbox", `"outbox"`},
		{"embedded double quote", `a"b`, `"a""b"`},
		{"quote-out attempt stays quoted", `x" ; DROP TABLE t --`, `"x"" ; DROP TABLE t --"`},
		// Documented divergence from lib/pq, which truncated at the NUL.
		{"NUL is stripped, not truncated at", "a\x00b", `"ab"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Identifier(c.in); got != c.want {
				t.Errorf("Identifier(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
