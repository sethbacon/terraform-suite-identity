// Package pgxparam supplies the parameter conversion this module's database
// mocks need in order to model the driver it actually runs on.
//
// pgx implements driver.NamedValueChecker and encodes Go values itself, so a
// []string bound to `= ANY($1)` is handed to the driver untouched. sqlmock does
// not, and falls back to database/sql's default converter, which accepts only
// the fixed driver.Value set and rejects any slice other than []byte with
// "unsupported type []string, a slice of string".
//
// That difference is invisible while a query builder wraps its arguments the
// way lib/pq's Array did — the wrapper pre-encoded the slice to a string, so
// the mock never saw a slice. Passing the slice directly, which is what pgx
// wants, makes the gap appear as a test failure rather than a behaviour change.
// Converter closes it so the mock accepts what the real driver accepts.
package pgxparam

import (
	"database/sql/driver"
	"reflect"
)

// Converter passes slices through and defers everything else to database/sql.
type Converter struct{}

// ConvertValue implements driver.ValueConverter.
func (Converter) ConvertValue(v any) (driver.Value, error) {
	// []byte is already a driver.Value and carries its own semantics; only
	// slices the default converter would reject are passed through.
	if _, ok := v.([]byte); !ok && v != nil {
		if reflect.TypeOf(v).Kind() == reflect.Slice {
			return v, nil
		}
	}
	return driver.DefaultParameterConverter.ConvertValue(v)
}
