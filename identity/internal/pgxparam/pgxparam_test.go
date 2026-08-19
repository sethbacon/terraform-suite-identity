package pgxparam

import (
	"database/sql/driver"
	"testing"
	"time"
)

func TestConverterPassesSlicesThrough(t *testing.T) {
	// The reason this package exists: database/sql's default converter rejects
	// these outright, and they are what an org-scope predicate binds.
	cases := []struct {
		name string
		in   any
	}{
		{"string slice", []string{"org-1", "org-2"}},
		{"empty string slice", []string{}},
		{"int slice", []int64{1, 2, 3}},
		{"nil string slice", []string(nil)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Converter{}.ConvertValue(c.in)
			if err != nil {
				t.Fatalf("ConvertValue(%#v) errored: %v", c.in, err)
			}
			if _, isDefault := driver.DefaultParameterConverter.ConvertValue(c.in); isDefault == nil {
				t.Fatalf("%#v no longer needs this converter; database/sql now accepts it", c.in)
			}
			// Passed through unchanged, so an expectation can compare against
			// the value the caller actually bound.
			if gotSlice, ok := got.([]string); ok {
				want, _ := c.in.([]string)
				if len(gotSlice) != len(want) {
					t.Errorf("ConvertValue returned %#v, want %#v", got, c.in)
				}
			}
		})
	}
}

func TestConverterDefersEverythingElse(t *testing.T) {
	// []byte is already a driver.Value and must keep its own semantics rather
	// than be caught by the slice branch.
	now := time.Now()
	cases := []struct {
		name string
		in   any
		want driver.Value
	}{
		{"byte slice", []byte("raw"), []byte("raw")},
		{"string", "org-1", "org-1"},
		{"int", 7, int64(7)},
		{"bool", true, true},
		{"nil", nil, nil},
		{"time", now, now},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Converter{}.ConvertValue(c.in)
			if err != nil {
				t.Fatalf("ConvertValue(%#v) errored: %v", c.in, err)
			}
			want, err := driver.DefaultParameterConverter.ConvertValue(c.in)
			if err != nil {
				t.Fatalf("the default converter rejected %#v: %v", c.in, err)
			}
			if gotBytes, ok := got.([]byte); ok {
				wantBytes, _ := want.([]byte)
				if string(gotBytes) != string(wantBytes) {
					t.Errorf("ConvertValue(%#v) = %v, want %v", c.in, got, want)
				}
				return
			}
			if got != want {
				t.Errorf("ConvertValue(%#v) = %v (%T), want %v (%T)", c.in, got, got, want, want)
			}
		})
	}
}

func TestConverterRejectsWhatTheDefaultRejects(t *testing.T) {
	// A non-slice the default converter cannot handle must still be an error,
	// so this stays a narrow widening rather than a blanket pass-through.
	if _, err := (Converter{}).ConvertValue(struct{ A int }{1}); err == nil {
		t.Error("a struct was accepted; the converter is wider than intended")
	}
}
