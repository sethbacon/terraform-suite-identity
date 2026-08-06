package notify

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// ddlColumn matches one column definition line in ChannelTableDDL. The DDL
// indents column definitions by four spaces and starts every type in upper case,
// which is what separates a column line from the trailing index statement's
// `    ON notification_channels (name);`.
var ddlColumn = regexp.MustCompile(`(?m)^ {4}([a-z_]+)\s+[A-Z]`)

func ddlColumns(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, m := range ddlColumn.FindAllStringSubmatch(ChannelTableDDL, -1) {
		out = append(out, m[1])
	}
	if len(out) == 0 {
		t.Fatal("parsed no columns out of ChannelTableDDL — this check would pass vacuously")
	}
	sort.Strings(out)
	return out
}

// daoColumns is the select/returning list every ChannelRepository statement uses.
func daoColumns(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, c := range strings.Split(channelColumns, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		t.Fatal("parsed no columns out of channelColumns — this check would pass vacuously")
	}
	sort.Strings(out)
	return out
}

func requirementNames(t *testing.T) []string {
	t.Helper()
	names := sortedRequirementNames()
	if len(names) == 0 {
		t.Fatal("channelColumnRequirements is empty — this check would pass vacuously")
	}
	return names
}

// TestChannelTableDDLDeclaresExactlyTheColumnsTheDAORequires is the check that
// replaces the prose contract this package used to ship.
//
// Three inventories have to agree: the columns the DAO selects (channelColumns),
// the columns the startup assertion demands (channelColumnRequirements), and the
// columns the canonical DDL creates (ChannelTableDDL). A consuming app builds
// its migration from the third and is checked against the second while the first
// is what actually runs, so any pair drifting apart reappears as a scan failure
// inside notification delivery — the exact failure mode issue #141 describes.
func TestChannelTableDDLDeclaresExactlyTheColumnsTheDAORequires(t *testing.T) {
	dao := strings.Join(daoColumns(t), ",")
	ddl := strings.Join(ddlColumns(t), ",")
	req := strings.Join(requirementNames(t), ",")

	if dao != ddl {
		t.Errorf("ChannelTableDDL creates columns [%s] but the DAO's statements address [%s]. "+
			"A consuming app that applies the shipped DDL would then fail a scan or a bind "+
			"at delivery time.", ddl, dao)
	}
	if dao != req {
		t.Errorf("channelColumnRequirements covers [%s] but the DAO's statements address [%s]. "+
			"An uncovered column is one VerifyChannelTable does not check, so its drift is "+
			"discovered by the notifier instead.", req, dao)
	}
}

// TestChannelTableDDLIsUnqualified pins the DDL to the same routing rule as the
// queries: the migration connection's search_path places the table, exactly as
// the repository connection's search_path later finds it. A schema baked into
// the shipped DDL would put the table somewhere the reading connection may not
// look.
func TestChannelTableDDLIsUnqualified(t *testing.T) {
	if !strings.Contains(ChannelTableDDL, "CREATE TABLE IF NOT EXISTS "+ChannelTable+" (") {
		t.Errorf("ChannelTableDDL does not create an unqualified %s. The consuming app owns "+
			"the table and its schema; qualifying it here would place it somewhere the "+
			"repository's connection may not resolve.", ChannelTable)
	}
}

// channelSchemaRows builds a catalogue result for a table with the canonical
// shape, with the named column overridden (type, notNull) or dropped when
// dataType is empty.
func channelSchemaRows(schema, override, dataType string, notNull bool, drop bool) *sqlmock.Rows {
	rows := sqlmock.NewRows([]string{"nspname", "attname", "format_type", "attnotnull"})
	canonical := map[string]struct {
		dataType string
		notNull  bool
	}{
		"id":               {"uuid", true},
		"name":             {"text", true},
		"type":             {"text", true},
		"encrypted_target": {"text", true},
		"events":           {"jsonb", true},
		"enabled":          {"boolean", true},
		"last_status":      {"text", false},
		"last_error":       {"text", false},
		"last_sent_at":     {"timestamp with time zone", false},
		"created_at":       {"timestamp with time zone", true},
		"updated_at":       {"timestamp with time zone", true},
	}
	for _, name := range sortedRequirementNames() {
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

func expectChannelSchema(mock sqlmock.Sqlmock, rows *sqlmock.Rows) {
	mock.ExpectQuery("current_setting").
		WillReturnRows(sqlmock.NewRows([]string{"current_setting"}).AddRow("identity, public"))
	mock.ExpectQuery("pg_catalog[.]pg_attribute").WillReturnRows(rows)
}

func TestVerifyChannelTable_AcceptsTheCanonicalShape(t *testing.T) {
	repo, mock := newChannelRepo(t)
	expectChannelSchema(mock, channelSchemaRows("public", "", "", false, false))

	got, err := VerifyChannelTable(context.Background(), repo.db)
	if err != nil {
		t.Fatalf("VerifyChannelTable on the canonical shape: %v", err)
	}
	if got != "public."+ChannelTable {
		t.Errorf("resolved name = %q, want %q", got, "public."+ChannelTable)
	}
}

func TestVerifyChannelTable_AcceptsVarcharForTextColumns(t *testing.T) {
	repo, mock := newChannelRepo(t)
	expectChannelSchema(mock, channelSchemaRows("app", "name", "character varying(255)", true, false))

	got, err := VerifyChannelTable(context.Background(), repo.db)
	if err != nil {
		t.Fatalf("varchar(255) must satisfy a text column — every statement here behaves "+
			"identically on both, and failing a working deployment is how an assertion gets "+
			"switched off: %v", err)
	}
	if got != "app."+ChannelTable {
		t.Errorf("resolved name = %q, want %q", got, "app."+ChannelTable)
	}
}

func TestVerifyChannelTable_RejectsTheDriftThatActuallyShipped(t *testing.T) {
	// Every case below is a shape one consuming app really had, or the
	// nullability the DAO's non-pointer scan targets cannot survive.
	cases := []struct {
		name     string
		column   string
		dataType string
		notNull  bool
		drop     bool
		wantIn   string
	}{
		{"events as text[]", "events", "text[]", true, false, "events is text[]"},
		{"events as json", "events", "json", true, false, "events is json"},
		{"encrypted_target as bytea", "encrypted_target", "bytea", true, false, "encrypted_target is bytea"},
		{"timestamps without a zone", "created_at", "timestamp without time zone", true, false, "created_at is timestamp without time zone"},
		{"enabled as text", "enabled", "text", true, false, "enabled is text"},
		{"a nullable NOT NULL column", "name", "text", false, false, "name is nullable"},
		{"a missing column", "last_sent_at", "", false, true, "last_sent_at is missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo, mock := newChannelRepo(t)
			expectChannelSchema(mock, channelSchemaRows("public", tc.column, tc.dataType, tc.notNull, tc.drop))

			got, err := VerifyChannelTable(context.Background(), repo.db)
			if err == nil {
				t.Fatalf("VerifyChannelTable accepted %s; that shape fails inside notification "+
					"delivery instead, which is the failure this assertion exists to move to "+
					"startup", tc.name)
			}
			if !errors.Is(err, ErrChannelTable) {
				t.Errorf("error does not wrap ErrChannelTable: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error does not name the offending column (%q):\n%v", tc.wantIn, err)
			}
			// The resolved name is still reported on failure: an operator
			// needs to know WHICH table is wrong before fixing it.
			if got != "public."+ChannelTable {
				t.Errorf("resolved name = %q on failure, want %q", got, "public."+ChannelTable)
			}
		})
	}
}

func TestVerifyChannelTable_ReportsATableThatResolvesToNothing(t *testing.T) {
	repo, mock := newChannelRepo(t)
	mock.ExpectQuery("current_setting").
		WillReturnRows(sqlmock.NewRows([]string{"current_setting"}).AddRow(`"$user", public`))
	mock.ExpectQuery("pg_catalog[.]pg_attribute").
		WillReturnRows(sqlmock.NewRows([]string{"nspname", "attname", "format_type", "attnotnull"}))

	got, err := VerifyChannelTable(context.Background(), repo.db)
	if err == nil {
		t.Fatal("VerifyChannelTable accepted a name that resolves to no table at all")
	}
	if !errors.Is(err, ErrChannelTable) {
		t.Errorf("error does not wrap ErrChannelTable: %v", err)
	}
	if got != "" {
		t.Errorf("resolved name = %q, want empty when nothing resolved", got)
	}
	for _, want := range []string{"resolves to nothing", `$user`, "ChannelTableDDL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error omits %q, which is what an operator needs to act on:\n%v", want, err)
		}
	}
}

func TestVerifyChannelTable_RejectsANilHandle(t *testing.T) {
	if _, err := VerifyChannelTable(context.Background(), nil); !errors.Is(err, ErrChannelTable) {
		t.Errorf("VerifyChannelTable(nil) = %v, want an error wrapping ErrChannelTable", err)
	}
}

func TestVerifyChannelTable_PropagatesQueryFailures(t *testing.T) {
	t.Run("search_path", func(t *testing.T) {
		repo, mock := newChannelRepo(t)
		mock.ExpectQuery("current_setting").WillReturnError(errDB)
		if _, err := VerifyChannelTable(context.Background(), repo.db); !errors.Is(err, errDB) {
			t.Errorf("err = %v, want it to wrap the driver error", err)
		}
	})
	t.Run("catalogue", func(t *testing.T) {
		repo, mock := newChannelRepo(t)
		mock.ExpectQuery("current_setting").
			WillReturnRows(sqlmock.NewRows([]string{"current_setting"}).AddRow("public"))
		mock.ExpectQuery("pg_catalog[.]pg_attribute").WillReturnError(errDB)
		if _, err := VerifyChannelTable(context.Background(), repo.db); !errors.Is(err, errDB) {
			t.Errorf("err = %v, want it to wrap the driver error", err)
		}
	})
	t.Run("scan", func(t *testing.T) {
		repo, mock := newChannelRepo(t)
		mock.ExpectQuery("current_setting").
			WillReturnRows(sqlmock.NewRows([]string{"current_setting"}).AddRow("public"))
		mock.ExpectQuery("pg_catalog[.]pg_attribute").WillReturnRows(
			sqlmock.NewRows([]string{"nspname", "attname", "format_type", "attnotnull"}).
				AddRow("public", "id", "uuid", "not-a-bool"))
		if _, err := VerifyChannelTable(context.Background(), repo.db); err == nil {
			t.Error("VerifyChannelTable ignored a catalogue row it could not scan")
		}
	})
}

func TestTypeSatisfiesIgnoresLengthModifiers(t *testing.T) {
	accepted := []string{"text", "character varying"}
	for _, tc := range []struct {
		dataType string
		want     bool
	}{
		{"text", true},
		{"character varying(255)", true},
		{"character varying", true},
		{"character(10)", false},
		{"jsonb", false},
	} {
		if got := typeSatisfies(tc.dataType, accepted); got != tc.want {
			t.Errorf("typeSatisfies(%q, %v) = %v, want %v", tc.dataType, accepted, got, tc.want)
		}
	}
}
