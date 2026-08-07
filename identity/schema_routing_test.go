package identity

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

var errRouting = errors.New("connection reset by peer")

// routingRows builds a catalogue result placing every repository table in
// schema, with the named table overridden (schema, relkind) or dropped.
func routingRows(schema, override, overrideSchema, kind string, drop bool) *sqlmock.Rows {
	rows := sqlmock.NewRows([]string{"name", "nspname", "relkind"})
	for _, table := range repositoryTables {
		s, k := schema, "r"
		if table == override {
			if drop {
				continue
			}
			s, k = overrideSchema, kind
		}
		rows.AddRow(table, s, k)
	}
	return rows
}

func expectRouting(mock sqlmock.Sqlmock, searchPath string, rows *sqlmock.Rows) {
	mock.ExpectQuery("current_setting").
		WillReturnRows(sqlmock.NewRows([]string{"current_setting"}).AddRow(searchPath))
	mock.ExpectQuery("unnest").WillReturnRows(rows)
}

func newRoutingDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, mock
}

func TestRepositoryTablesReturnsACopy(t *testing.T) {
	got := RepositoryTables()
	if len(got) == 0 {
		t.Fatal("RepositoryTables() is empty — VerifySchemaRouting would pass vacuously")
	}
	got[0] = "clobbered"
	if RepositoryTables()[0] == "clobbered" {
		t.Error("RepositoryTables() hands out its backing array, so a caller can shrink or " +
			"rewrite the set the startup assertion checks")
	}
}

func TestTableRoutingQualified(t *testing.T) {
	if got := (TableRouting{Table: "users", Schema: "identity"}).Qualified(); got != "identity.users" {
		t.Errorf("Qualified() = %q, want %q", got, "identity.users")
	}
	if got := (TableRouting{Table: "users"}).Qualified(); got != "" {
		t.Errorf("Qualified() = %q, want %q for a name that resolved to nothing", got, "")
	}
}

func TestVerifySchemaRouting_AcceptsTheIntendedSchema(t *testing.T) {
	for _, schema := range []string{SchemaName, "public"} {
		t.Run(schema, func(t *testing.T) {
			db, mock := newRoutingDB(t)
			expectRouting(mock, schema+", public", routingRows(schema, "", "", "", false))

			if err := VerifySchemaRouting(context.Background(), db, schema); err != nil {
				t.Fatalf("VerifySchemaRouting(..., %q) rejected a connection that resolves "+
					"every table there: %v", schema, err)
			}
		})
	}
}

// TestVerifySchemaRouting_DetectsTheSplitBrainRouting is the unit-level form of
// the defect: the identity schema exists, the connection reaches the app's own
// identically-shaped tables instead, and every query would have succeeded.
func TestVerifySchemaRouting_DetectsTheSplitBrainRouting(t *testing.T) {
	db, mock := newRoutingDB(t)
	expectRouting(mock, `"$user", public`, routingRows("public", "", "", "", false))

	err := VerifySchemaRouting(context.Background(), db, SchemaName)
	if err == nil {
		t.Fatal("VerifySchemaRouting accepted a connection whose every table resolves to " +
			"public while the deployment asked for the identity schema")
	}
	if !errors.Is(err, ErrSchemaRouting) {
		t.Errorf("error does not wrap ErrSchemaRouting: %v", err)
	}
	for _, want := range []string{"users resolves to public.users", "$user", "8 of 8"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error omits %q, which is what an operator needs to act on:\n%v", want, err)
		}
	}
}

func TestVerifySchemaRouting_DetectsOneStrayTable(t *testing.T) {
	db, mock := newRoutingDB(t)
	expectRouting(mock, "identity, public", routingRows(SchemaName, "audit_logs", "public", "r", false))

	err := VerifySchemaRouting(context.Background(), db, SchemaName)
	if err == nil {
		t.Fatal("VerifySchemaRouting accepted a routing that splits one table off into " +
			"another schema — a partial cutover is the split-brain, not a lesser version of it")
	}
	if !strings.Contains(err.Error(), "audit_logs resolves to public.audit_logs") {
		t.Errorf("error does not name the stray table:\n%v", err)
	}
	if strings.Contains(err.Error(), "users resolves") {
		t.Errorf("error blames tables that resolved correctly:\n%v", err)
	}
}

func TestVerifySchemaRouting_DetectsAnUnresolvedTable(t *testing.T) {
	db, mock := newRoutingDB(t)
	expectRouting(mock, "identity", routingRows(SchemaName, "revoked_tokens", "", "", true))
	// One row short: ResolveRouting must not quietly check a smaller set than
	// it was asked for.
	err := VerifySchemaRouting(context.Background(), db, SchemaName)
	if err == nil {
		t.Fatal("VerifySchemaRouting accepted a catalogue answer with a table missing")
	}
	if !errors.Is(err, ErrSchemaRouting) {
		t.Errorf("error does not wrap ErrSchemaRouting: %v", err)
	}
}

func TestVerifySchemaRouting_DetectsANameThatResolvesToNothing(t *testing.T) {
	db, mock := newRoutingDB(t)
	rows := sqlmock.NewRows([]string{"name", "nspname", "relkind"})
	for _, table := range repositoryTables {
		if table == "users" {
			rows.AddRow(table, "", "")
			continue
		}
		rows.AddRow(table, SchemaName, "r")
	}
	expectRouting(mock, "identity", rows)

	err := VerifySchemaRouting(context.Background(), db, SchemaName)
	if err == nil {
		t.Fatal("VerifySchemaRouting accepted a connection on which users resolves to nothing")
	}
	if !strings.Contains(err.Error(), "users resolves to nothing") {
		t.Errorf("error does not say the name resolved to nothing:\n%v", err)
	}
}

// TestVerifySchemaRouting_RejectsANonTableRelation covers the reason the check
// reads relkind at all: to_regclass resolves ANY relation, so a sequence or an
// index carrying a table's name resolves in the right schema and would otherwise
// be reported as correct routing.
func TestVerifySchemaRouting_RejectsANonTableRelation(t *testing.T) {
	db, mock := newRoutingDB(t)
	expectRouting(mock, "identity", routingRows(SchemaName, "users", SchemaName, "S", false))

	err := VerifySchemaRouting(context.Background(), db, SchemaName)
	if err == nil {
		t.Fatal("VerifySchemaRouting accepted a sequence standing where the users table " +
			"should be")
	}
	if !strings.Contains(err.Error(), "not a table a repository can read or write") {
		t.Errorf("error does not explain the relkind rejection:\n%v", err)
	}
}

func TestVerifySchemaRouting_AcceptsAViewOverTheTables(t *testing.T) {
	db, mock := newRoutingDB(t)
	expectRouting(mock, "identity", routingRows(SchemaName, "users", SchemaName, "v", false))

	if err := VerifySchemaRouting(context.Background(), db, SchemaName); err != nil {
		t.Fatalf("a view is a legitimate way to front the real table and every statement "+
			"here works through one: %v", err)
	}
}

func TestVerifySchemaRouting_RequiresASchema(t *testing.T) {
	db, _ := newRoutingDB(t)
	if err := VerifySchemaRouting(context.Background(), db, "  "); !errors.Is(err, ErrSchemaRouting) {
		t.Errorf("VerifySchemaRouting with no schema = %v, want an error wrapping "+
			"ErrSchemaRouting: the schema is the deployment's statement of intent and "+
			"defaulting it would put the assumption back", err)
	}
}

func TestVerifySchemaRouting_RejectsANilHandle(t *testing.T) {
	if err := VerifySchemaRouting(context.Background(), nil, SchemaName); !errors.Is(err, ErrSchemaRouting) {
		t.Errorf("VerifySchemaRouting(nil) = %v, want an error wrapping ErrSchemaRouting", err)
	}
}

func TestResolveRouting_ReportsSearchPathAndSchemas(t *testing.T) {
	db, mock := newRoutingDB(t)
	expectRouting(mock, "identity, public", routingRows(SchemaName, "", "", "", false))

	routing, err := ResolveRouting(context.Background(), db)
	if err != nil {
		t.Fatalf("ResolveRouting: %v", err)
	}
	if routing.SearchPath != "identity, public" {
		t.Errorf("SearchPath = %q, want %q", routing.SearchPath, "identity, public")
	}
	if len(routing.Tables) != len(repositoryTables) {
		t.Fatalf("got %d routings, want %d", len(routing.Tables), len(repositoryTables))
	}
	if got := routing.Tables[0].Qualified(); got != SchemaName+"."+repositoryTables[0] {
		t.Errorf("first routing = %q, want %q", got, SchemaName+"."+repositoryTables[0])
	}
}

func TestResolveRouting_AcceptsAnExplicitTableList(t *testing.T) {
	db, mock := newRoutingDB(t)
	mock.ExpectQuery("current_setting").
		WillReturnRows(sqlmock.NewRows([]string{"current_setting"}).AddRow("public"))
	mock.ExpectQuery("unnest").WillReturnRows(
		sqlmock.NewRows([]string{"name", "nspname", "relkind"}).AddRow("system_settings", "public", "r"))

	routing, err := ResolveRouting(context.Background(), db, "system_settings")
	if err != nil {
		t.Fatalf("ResolveRouting: %v", err)
	}
	if len(routing.Tables) != 1 || routing.Tables[0].Qualified() != "public.system_settings" {
		t.Errorf("routing = %+v, want the one requested name resolved in public", routing.Tables)
	}
}

func TestResolveRouting_PropagatesFailures(t *testing.T) {
	t.Run("search_path", func(t *testing.T) {
		db, mock := newRoutingDB(t)
		mock.ExpectQuery("current_setting").WillReturnError(errRouting)
		if _, err := ResolveRouting(context.Background(), db); !errors.Is(err, errRouting) {
			t.Errorf("err = %v, want it to wrap the driver error", err)
		}
	})
	t.Run("catalogue", func(t *testing.T) {
		db, mock := newRoutingDB(t)
		mock.ExpectQuery("current_setting").
			WillReturnRows(sqlmock.NewRows([]string{"current_setting"}).AddRow("public"))
		mock.ExpectQuery("unnest").WillReturnError(errRouting)
		if _, err := ResolveRouting(context.Background(), db); !errors.Is(err, errRouting) {
			t.Errorf("err = %v, want it to wrap the driver error", err)
		}
	})
	t.Run("scan", func(t *testing.T) {
		db, mock := newRoutingDB(t)
		mock.ExpectQuery("current_setting").
			WillReturnRows(sqlmock.NewRows([]string{"current_setting"}).AddRow("public"))
		mock.ExpectQuery("unnest").WillReturnRows(
			sqlmock.NewRows([]string{"name", "nspname", "relkind"}).AddRow(nil, nil, nil))
		if _, err := ResolveRouting(context.Background(), db); err == nil {
			t.Error("ResolveRouting ignored a catalogue row it could not scan")
		}
	})
	t.Run("closed pool", func(t *testing.T) {
		db, _, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock.New: %v", err)
		}
		_ = db.Close()
		if _, err := ResolveRouting(context.Background(), db); !errors.Is(err, ErrSchemaRouting) {
			t.Errorf("err = %v, want an error wrapping ErrSchemaRouting when no connection "+
				"can be borrowed", err)
		}
	})
}
