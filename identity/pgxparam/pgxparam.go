// Package pgxparam lets a database mock accept the arguments this library
// binds.
//
// identity/store's OrgScope.SQL and its siblings return a bare []string for the
// `= ANY($n)` tenant predicate, because that is what the driver wants: pgx implements
// driver.NamedValueChecker and encodes Go values itself, and lib/pq does the
// same, auto-wrapping any slice through its own Array. sqlmock does neither. It
// falls back to database/sql's default converter, which accepts only the fixed
// driver.Value set and rejects every slice but []byte:
//
//	sql: converting argument $1 type: unsupported type []string, a slice of string
//
// So a consumer mocking a scoped query fails on an argument both real drivers
// accept. Build the mock with this converter and it does not:
//
//	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(pgxparam.Converter{}))
//
// This is exported rather than kept internal because the mismatch follows from
// this library's own public API. A consumer cannot avoid it by writing its
// queries differently, and every consumer that mocks one needs the same twenty
// lines — which is exactly the kind of thing that drifts once it is copied.
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
