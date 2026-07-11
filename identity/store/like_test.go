package store

import "testing"

func TestEscapeLikePattern(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "alice", "alice"},
		{"percent", "50%", `50\%`},
		{"underscore", "a_b", `a\_b`},
		{"backslash", `a\b`, `a\\b`},
		{"all metacharacters", `%_\`, `\%\_\\`},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := escapeLikePattern(tc.in); got != tc.want {
				t.Errorf("escapeLikePattern(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
