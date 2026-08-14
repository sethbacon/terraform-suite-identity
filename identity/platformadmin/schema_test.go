package platformadmin

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// ddlColumn matches one column definition line in the generated DDL. Column
// definitions are indented four spaces and every type starts upper case.
var ddlColumn = regexp.MustCompile(`(?m)^ {4}([a-z_]+)\s+[A-Z]`)

func ddlColumns(t *testing.T) []string {
	t.Helper()
	ddl, err := TableDDL("platform_admins")
	if err != nil {
		t.Fatalf("TableDDL: %v", err)
	}
	var out []string
	for _, m := range ddlColumn.FindAllStringSubmatch(ddl, -1) {
		out = append(out, m[1])
	}
	if len(out) == 0 {
		t.Fatal("parsed no columns out of TableDDL — this check would pass vacuously")
	}
	sort.Strings(out)
	return out
}

// statementColumns is the projection every carrier read scans.
func statementColumns(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, c := range strings.Split(grantColumns, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		t.Fatal("parsed no columns out of grantColumns — this check would pass vacuously")
	}
	sort.Strings(out)
	return out
}

func requirementNames(t *testing.T) []string {
	t.Helper()
	names := make([]string, 0, len(columnRequirements))
	for name := range columnRequirements {
		names = append(names, name)
	}
	if len(names) == 0 {
		t.Fatal("columnRequirements is empty — this check would pass vacuously")
	}
	sort.Strings(names)
	return names
}

// TestTableDDLDeclaresExactlyTheColumnsTheStatementsAddress is the check that
// replaces a prose contract.
//
// Three inventories have to agree: the columns the carrier's statements scan
// (grantColumns), the columns the startup assertion demands (columnRequirements),
// and the columns the canonical DDL creates (TableDDL). The consuming app builds
// its migration from the third and is checked against the second while the first
// is what actually runs, so any pair drifting apart reappears as a scan failure
// inside a grant or a revoke.
func TestTableDDLDeclaresExactlyTheColumnsTheStatementsAddress(t *testing.T) {
	stmts := strings.Join(statementColumns(t), ",")
	ddl := strings.Join(ddlColumns(t), ",")
	req := strings.Join(requirementNames(t), ",")

	if stmts != ddl {
		t.Errorf("TableDDL creates columns [%s] but the carrier's statements address [%s]. "+
			"An app that applied the shipped DDL would fail a scan or a bind at grant time.", ddl, stmts)
	}
	if stmts != req {
		t.Errorf("columnRequirements covers [%s] but the carrier's statements address [%s]. "+
			"An uncovered column is one VerifyTable does not check, so its drift is discovered "+
			"by a failed revocation instead.", req, stmts)
	}
}

// The DDL is generated for the app's OWN table, so it must accept the same names
// New does — and refuse the same ones.
func TestTableDDLIsParameterisedAndValidatedLikeNew(t *testing.T) {
	ddl, err := TableDDL("registry.platform_admins")
	if err != nil {
		t.Fatalf("TableDDL: %v", err)
	}
	if !strings.Contains(ddl, `CREATE TABLE IF NOT EXISTS "registry"."platform_admins"`) {
		t.Errorf("TableDDL did not create the qualified table the app asked for:\n%s", ddl)
	}
	if _, err := TableDDL(`platform_admins"; DROP TABLE users --`); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("TableDDL err = %v, want ErrNotConfigured — a name New would refuse must not be "+
			"creatable here either", err)
	}
}

// GUARD on-conflict-needs-an-arbiter. Grant's ON CONFLICT (user_id) DO NOTHING
// is what preserves the original provenance across a re-grant, and it requires a
// unique index on exactly that column. The DDL must declare it.
func TestTableDDLMakesUserIDTheArbiterForOnConflict(t *testing.T) {
	ddl, err := TableDDL("platform_admins")
	if err != nil {
		t.Fatalf("TableDDL: %v", err)
	}
	if !regexp.MustCompile(`(?m)^\s*user_id\s+UUID\s+PRIMARY KEY`).MatchString(ddl) {
		t.Errorf("TableDDL does not declare user_id as the PRIMARY KEY, so Grant's "+
			"ON CONFLICT (user_id) has no arbiter and every grant would fail:\n%s", ddl)
	}
}

// GUARD no-foreign-keys-across-the-identity-boundary. Identity may live in
// another schema or another database, where an FK is not expressible at all. A
// well-meaning "improvement" that adds REFERENCES users(id) here would make the
// shipped DDL fail to apply in a supported topology.
func TestTableDDLCarriesNoForeignKeys(t *testing.T) {
	ddl, err := TableDDL("platform_admins")
	if err != nil {
		t.Fatalf("TableDDL: %v", err)
	}
	if strings.Contains(strings.ToUpper(ddl), "REFERENCES") {
		t.Errorf("TableDDL declares a foreign key. Identity may live in another database, where "+
			"Postgres has no cross-database foreign keys at all; see schema.go for the full "+
			"reasoning before changing this:\n%s", ddl)
	}
}

// ---------------------------------------------------------------------------
// VerifyTable
// ---------------------------------------------------------------------------

func carrierShapeRows(schema, override, dataType string, notNull bool, drop bool) *sqlmock.Rows {
	rows := sqlmock.NewRows([]string{"nspname", "attname", "format_type", "attnotnull"})
	canonical := map[string]actualColumn{
		"user_id":    {"uuid", true},
		"granted_by": {"uuid", false},
		"granted_at": {"timestamp with time zone", true},
		"note":       {"text", false},
	}
	for _, name := range []string{"user_id", "granted_by", "granted_at", "note"} {
		col := canonical[name]
		if name == override {
			if drop {
				continue
			}
			col.dataType, col.notNull = dataType, notNull
		}
		rows.AddRow(schema, name, col.dataType, col.notNull)
	}
	return rows
}

func expectCarrierShape(mock sqlmock.Sqlmock, rows *sqlmock.Rows, hasUnique bool) {
	mock.ExpectQuery("current_setting").
		WillReturnRows(sqlmock.NewRows([]string{"current_setting"}).AddRow("registry, public"))
	mock.ExpectQuery("pg_catalog[.]pg_attribute").WillReturnRows(rows)
	mock.ExpectQuery("pg_catalog[.]pg_index").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(hasUnique))
}

func TestVerifyTableAcceptsTheCanonicalShapeAndReportsWhereItResolved(t *testing.T) {
	c, mock := newTestCarrier(t)
	expectCarrierShape(mock, carrierShapeRows("registry", "", "", false, false), true)

	got, err := c.VerifyTable(context.Background())
	if err != nil {
		t.Fatalf("VerifyTable on the canonical shape: %v", err)
	}
	// The resolved schema is the point: the table is app-owned and this module
	// does not know which schema it should be in, so the operator is told where
	// grants are actually being read from rather than assuming.
	if got != "registry.platform_admins" {
		t.Errorf("resolved name = %q, want %q", got, "registry.platform_admins")
	}
}

func TestVerifyTableAcceptsTextForUUIDColumns(t *testing.T) {
	c, mock := newTestCarrier(t)
	expectCarrierShape(mock, carrierShapeRows("app", "user_id", "character varying(64)", true, false), true)

	got, err := c.VerifyTable(context.Background())
	if err != nil {
		t.Fatalf("varchar must satisfy a user_id column — every statement here binds and scans a "+
			"string, and failing a working deployment is how an assertion gets switched off: %v", err)
	}
	if got != "app.platform_admins" {
		t.Errorf("resolved name = %q, want %q", got, "app.platform_admins")
	}
}

func TestVerifyTableRejectsShapesTheStatementsCannotSurvive(t *testing.T) {
	cases := []struct {
		name     string
		column   string
		dataType string
		notNull  bool
		drop     bool
		want     string
	}{
		{
			name: "granted_at as timestamp without time zone", column: "granted_at",
			dataType: "timestamp without time zone", notNull: true,
			want: "granted_at is timestamp without time zone",
		},
		{
			name: "granted_at nullable", column: "granted_at",
			dataType: "timestamp with time zone", notNull: false,
			want: "granted_at is nullable",
		},
		{
			name: "user_id nullable", column: "user_id",
			dataType: "uuid", notNull: false,
			want: "user_id is nullable",
		},
		{
			name: "note missing entirely", column: "note", drop: true,
			want: "note is missing",
		},
		{
			name: "granted_by as jsonb", column: "granted_by",
			dataType: "jsonb",
			want:     "granted_by is jsonb",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, mock := newTestCarrier(t)
			expectCarrierShape(mock, carrierShapeRows("registry", tc.column, tc.dataType, tc.notNull, tc.drop), true)

			got, err := c.VerifyTable(context.Background())
			if err == nil {
				t.Fatalf("VerifyTable accepted %s; that shape fails inside a grant or a revoke instead", tc.name)
			}
			if !errors.Is(err, ErrTableShape) {
				t.Fatalf("err = %v, want it to wrap ErrTableShape", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to name the problem (%q)", err, tc.want)
			}
			// The resolved name is still reported, so the operator knows WHICH
			// table is wrong.
			if got != "registry.platform_admins" {
				t.Errorf("resolved name = %q, want it reported alongside the failure", got)
			}
		})
	}
}

// GUARD on-conflict-needs-an-arbiter, at startup. A table with all four columns
// and no unique index on user_id passes every column check and then fails every
// grant with "there is no unique or exclusion constraint matching the ON
// CONFLICT specification".
func TestVerifyTableRejectsATableWithNoUniqueIndexOnUserID(t *testing.T) {
	c, mock := newTestCarrier(t)
	expectCarrierShape(mock, carrierShapeRows("registry", "", "", false, false), false)

	_, err := c.VerifyTable(context.Background())
	if !errors.Is(err, ErrTableShape) {
		t.Fatalf("err = %v, want ErrTableShape — without the index every grant fails at write time", err)
	}
	if !strings.Contains(err.Error(), "unique index on exactly (user_id)") {
		t.Errorf("err = %v, want it to name the missing arbiter", err)
	}
}

// A name that resolves to nothing is the most common misconfiguration — the
// app never applied TableDDL, or applied it into a schema this connection's
// search_path does not reach. The message has to say both.
func TestVerifyTableReportsATableThatResolvesToNothing(t *testing.T) {
	c, mock := newTestCarrier(t)
	mock.ExpectQuery("current_setting").
		WillReturnRows(sqlmock.NewRows([]string{"current_setting"}).AddRow(`"$user", public`))
	mock.ExpectQuery("pg_catalog[.]pg_attribute").
		WillReturnRows(sqlmock.NewRows([]string{"nspname", "attname", "format_type", "attnotnull"}))

	got, err := c.VerifyTable(context.Background())
	if !errors.Is(err, ErrTableShape) {
		t.Fatalf("err = %v, want ErrTableShape", err)
	}
	if got != "" {
		t.Errorf("resolved name = %q, want empty when nothing resolved", got)
	}
	for _, want := range []string{"resolves to nothing", `$user`, "TableDDL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to mention %q", err, want)
		}
	}
}

func TestVerifyTablePropagatesQueryFailures(t *testing.T) {
	errDB := errors.New("permission denied for schema pg_catalog")

	t.Run("search_path read fails", func(t *testing.T) {
		c, mock := newTestCarrier(t)
		mock.ExpectQuery("current_setting").WillReturnError(errDB)
		if _, err := c.VerifyTable(context.Background()); !errors.Is(err, errDB) {
			t.Errorf("err = %v, want %v", err, errDB)
		}
	})
	t.Run("catalogue read fails", func(t *testing.T) {
		c, mock := newTestCarrier(t)
		mock.ExpectQuery("current_setting").
			WillReturnRows(sqlmock.NewRows([]string{"current_setting"}).AddRow("registry"))
		mock.ExpectQuery("pg_catalog[.]pg_attribute").WillReturnError(errDB)
		if _, err := c.VerifyTable(context.Background()); !errors.Is(err, errDB) {
			t.Errorf("err = %v, want %v", err, errDB)
		}
	})
	t.Run("index read fails", func(t *testing.T) {
		c, mock := newTestCarrier(t)
		mock.ExpectQuery("current_setting").
			WillReturnRows(sqlmock.NewRows([]string{"current_setting"}).AddRow("registry"))
		mock.ExpectQuery("pg_catalog[.]pg_attribute").
			WillReturnRows(carrierShapeRows("registry", "", "", false, false))
		mock.ExpectQuery("pg_catalog[.]pg_index").WillReturnError(errDB)
		if _, err := c.VerifyTable(context.Background()); !errors.Is(err, errDB) {
			t.Errorf("err = %v, want %v", err, errDB)
		}
	})
	t.Run("a catalogue row that cannot be scanned", func(t *testing.T) {
		c, mock := newTestCarrier(t)
		mock.ExpectQuery("current_setting").
			WillReturnRows(sqlmock.NewRows([]string{"current_setting"}).AddRow("registry"))
		mock.ExpectQuery("pg_catalog[.]pg_attribute").
			WillReturnRows(sqlmock.NewRows([]string{"nspname"}).AddRow("registry"))
		if _, err := c.VerifyTable(context.Background()); err == nil {
			t.Error("VerifyTable ignored a catalogue row it could not scan")
		}
	})
}
