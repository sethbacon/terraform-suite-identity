package notify

import (
	"context"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/sethbacon/terraform-suite-identity/identity/pgxparam"
	"github.com/sethbacon/terraform-suite-identity/identity/store"
)

const (
	scopeTestChannelID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	scopeTestOrgA      = "11111111-1111-1111-1111-111111111111"
	scopeTestOrgB      = "22222222-2222-2222-2222-222222222222"
)

var scopeTestSentAt = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

// newScopedChannelRepo builds a repository whose mock compares SQL EXACTLY
// (whitespace-normalised) instead of treating the expectation as a regexp, and
// whose value converter accepts the []string the tenant predicate binds.
//
// Both options are load-bearing. The default regexp matcher would let a
// statement that gained an unexpected predicate still satisfy an expectation
// written for the statement without one, which is the single thing these tests
// exist to detect; and the default converter rejects []string outright, the
// mismatch identity/pgxparam documents.
func newScopedChannelRepo(t *testing.T) (*ChannelRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(
		sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual),
		sqlmock.ValueConverterOption(pgxparam.Converter{}),
	)
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewChannelRepository(db), mock
}

// channelStatement is one of the repository's row-selecting statements, in both
// spellings: the one it has always emitted, and the one it emits when the caller
// supplies a scope.
type channelStatement struct {
	name string
	// unscoped is the statement as this package shipped it before
	// ChannelQueryOption existed. It is written out rather than derived so
	// that changing it is a deliberate act — see
	// TestUnscopedStatementsAreUnchanged for what depends on that.
	unscoped string
	// scoped is the same statement carrying the predicate for a scope over a
	// single organization. The $N in it is the assertion that matters: the
	// placeholder index has to follow the arguments the statement already
	// binds, and Update binds six of them.
	scoped string
	// baseArgs are the arguments the statement binds regardless of scope.
	baseArgs []driver.Value
	// exec is true for statements driven through ExecContext rather than a
	// query.
	exec bool
	call func(r *ChannelRepository, opts ...ChannelQueryOption) error
}

func channelStatements() []channelStatement {
	eventsJSON := []byte(`["cve_detected"]`)
	return []channelStatement{
		{
			name:     "List",
			unscoped: `SELECT ` + channelColumns + ` FROM notification_channels ORDER BY created_at DESC`,
			scoped: `SELECT ` + channelColumns + ` FROM notification_channels` +
				` WHERE organization_id = ANY($1) ORDER BY created_at DESC`,
			call: func(r *ChannelRepository, opts ...ChannelQueryOption) error {
				_, err := r.List(context.Background(), opts...)
				return err
			},
		},
		{
			name:     "GetByID",
			unscoped: `SELECT ` + channelColumns + ` FROM notification_channels WHERE id = $1`,
			scoped: `SELECT ` + channelColumns +
				` FROM notification_channels WHERE id = $1 AND organization_id = ANY($2)`,
			baseArgs: []driver.Value{scopeTestChannelID},
			call: func(r *ChannelRepository, opts ...ChannelQueryOption) error {
				_, err := r.GetByID(context.Background(), scopeTestChannelID, opts...)
				return err
			},
		},
		{
			name: "ListEnabledForEvent",
			unscoped: `SELECT ` + channelColumns + ` FROM notification_channels` +
				` WHERE enabled AND (jsonb_array_length(events) = 0 OR events @> to_jsonb($1::text))`,
			scoped: `SELECT ` + channelColumns + ` FROM notification_channels` +
				` WHERE enabled AND (jsonb_array_length(events) = 0 OR events @> to_jsonb($1::text))` +
				` AND organization_id = ANY($2)`,
			baseArgs: []driver.Value{"cve_detected"},
			call: func(r *ChannelRepository, opts ...ChannelQueryOption) error {
				_, err := r.ListEnabledForEvent(context.Background(), "cve_detected", opts...)
				return err
			},
		},
		{
			name: "Update",
			unscoped: `UPDATE notification_channels SET name=$2, type=$3, events=$4, enabled=$5,` +
				` encrypted_target=COALESCE($6, encrypted_target), updated_at=now()` +
				` WHERE id=$1 RETURNING ` + channelColumns,
			// $7, not $2: the scope is spliced after the six arguments the
			// SET clause and the id predicate already bind. A predicate that
			// renumbered them would bind the organization list to `name`.
			scoped: `UPDATE notification_channels SET name=$2, type=$3, events=$4, enabled=$5,` +
				` encrypted_target=COALESCE($6, encrypted_target), updated_at=now()` +
				` WHERE id=$1 AND organization_id = ANY($7) RETURNING ` + channelColumns,
			baseArgs: []driver.Value{scopeTestChannelID, "ops-webhook", "webhook", eventsJSON, true, "ENC"},
			call: func(r *ChannelRepository, opts ...ChannelQueryOption) error {
				_, err := r.Update(context.Background(), scopeTestChannelID, "ops-webhook", "webhook",
					[]string{"cve_detected"}, true, "ENC", opts...)
				return err
			},
		},
		{
			name:     "Delete",
			unscoped: `DELETE FROM notification_channels WHERE id = $1`,
			scoped:   `DELETE FROM notification_channels WHERE id = $1 AND organization_id = ANY($2)`,
			baseArgs: []driver.Value{scopeTestChannelID},
			exec:     true,
			call: func(r *ChannelRepository, opts ...ChannelQueryOption) error {
				return r.Delete(context.Background(), scopeTestChannelID, opts...)
			},
		},
		{
			name: "RecordDelivery",
			unscoped: `UPDATE notification_channels SET last_status=$2, last_error=NULLIF($3,''),` +
				` last_sent_at=$4, updated_at=now() WHERE id=$1`,
			scoped: `UPDATE notification_channels SET last_status=$2, last_error=NULLIF($3,''),` +
				` last_sent_at=$4, updated_at=now() WHERE id=$1 AND organization_id = ANY($5)`,
			baseArgs: []driver.Value{scopeTestChannelID, "sent", "", scopeTestSentAt},
			exec:     true,
			call: func(r *ChannelRepository, opts ...ChannelQueryOption) error {
				return r.RecordDelivery(context.Background(), scopeTestChannelID, "sent", "", scopeTestSentAt, opts...)
			},
		},
	}
}

// expectStatement arranges the mock for one statement's SQL and arguments.
func expectStatement(mock sqlmock.Sqlmock, st channelStatement, sql string, args []driver.Value) {
	if st.exec {
		mock.ExpectExec(sql).WithArgs(args...).WillReturnResult(sqlmock.NewResult(0, 1))
		return
	}
	mock.ExpectQuery(sql).WithArgs(args...).WillReturnRows(fullChannelRow(scopeTestChannelID, "ENC"))
}

// TestUnscopedStatementsAreUnchanged is a CONTRACT WITH THE OTHER CONSUMER, not
// a formatting check.
//
// terraform-registry reads this table through the same DAO against a
// notification_channels that has no organization_id column and no plan for one.
// If any statement here acquires a tenant predicate — even the harmless-looking
// `AND TRUE` that a "just always emit a WHERE and let TRUE mean unscoped"
// refactor produces — that consumer's queries change under it, and the ones that
// name the column fail outright at `column "organization_id" does not exist`.
//
// So the unscoped statements are pinned literally, and the mock matches SQL
// exactly rather than as a regexp. A failure here is not a test to update; it is
// a question to answer: does the other consumer still execute what it executed
// before?
func TestUnscopedStatementsAreUnchanged(t *testing.T) {
	for _, st := range channelStatements() {
		t.Run(st.name, func(t *testing.T) {
			repo, mock := newScopedChannelRepo(t)
			expectStatement(mock, st, st.unscoped, st.baseArgs)

			if err := st.call(repo); err != nil {
				t.Fatalf("%s with no options did not emit the statement this package has "+
					"always emitted: %v", st.name, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: %v", st.name, err)
			}
			if strings.Contains(st.unscoped, ChannelOrganizationColumn) {
				t.Errorf("the pinned unscoped %s names %s. The unscoped statement must not "+
					"mention a column the other consumer's table does not have",
					st.name, ChannelOrganizationColumn)
			}
		})
	}
}

// TestNilOptionIsIgnored covers the option slice a caller builds conditionally
// and leaves a nil in. Calling through it would panic inside the repository,
// which is a worse outcome than the unscoped statement it was already going to
// send.
func TestNilOptionIsIgnored(t *testing.T) {
	repo, mock := newScopedChannelRepo(t)
	st := channelStatements()[0] // List
	expectStatement(mock, st, st.unscoped, st.baseArgs)

	if _, err := repo.List(context.Background(), nil); err != nil {
		t.Fatalf("List with a nil option: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// TestScopedStatementsCarryTheTenantPredicate is the other direction: every
// statement, given a scope, constrains on the organization column and binds the
// allowlist at the placeholder that follows the arguments it already had.
//
// Update is the case worth reading. It binds six arguments before the scope, so
// a splice that assumed "$2" — the index a hand-written call site reaches for
// because the id is $1 — would bind the organization list to `name` and quietly
// rename every channel in the scope.
func TestScopedStatementsCarryTheTenantPredicate(t *testing.T) {
	for _, st := range channelStatements() {
		t.Run(st.name, func(t *testing.T) {
			repo, mock := newScopedChannelRepo(t)
			args := append(append([]driver.Value{}, st.baseArgs...), []string{scopeTestOrgA})
			expectStatement(mock, st, st.scoped, args)

			err := st.call(repo, WithOrgScope(store.OrgScopeOrganizations(scopeTestOrgA)))
			if err != nil {
				t.Fatalf("scoped %s: %v", st.name, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: %v", st.name, err)
			}
		})
	}
}

// TestScopeRenderingKeepsIdentityStoreSemantics pins the predicate each kind of
// OrgScope produces, on the one statement that has no WHERE clause of its own so
// the rendering is visible undiluted.
//
// The point is that this package adds NO semantics of its own. Every row here is
// what identity/store's OrgScope.SQL already means; a divergence would give the
// estate two answers to "what does an empty scope select", which is how the
// class org_scope.go describes reopens.
func TestScopeRenderingKeepsIdentityStoreSemantics(t *testing.T) {
	list := `SELECT ` + channelColumns + ` FROM notification_channels`
	order := ` ORDER BY created_at DESC`

	cases := []struct {
		name  string
		scope store.OrgScope
		want  string
		args  []driver.Value
		why   string
	}{
		{
			name:  "the zero scope denies",
			scope: store.OrgScope{},
			want:  list + ` WHERE FALSE` + order,
			why: "a caller who opted into scoping and then could not say which organization " +
				"they are in must see nothing, not everything",
		},
		{
			name:  "an empty allowlist denies",
			scope: store.OrgScopeOrganizations(),
			want:  list + ` WHERE FALSE` + order,
			why:   "a principal with no memberships has no channels, which is not a reason to widen the query",
		},
		{
			name:  "platform-wide reaches everything, in the statement",
			scope: store.OrgScopeAllOrganizations(),
			want:  list + ` WHERE TRUE` + order,
			why: "reaching every organization is a literal TRUE the database and any query log " +
				"can show, rather than an absent predicate indistinguishable from a bug",
		},
		{
			name:  "an allowlist binds the ids, sorted and deduplicated",
			scope: store.OrgScopeOrganizations(scopeTestOrgB, scopeTestOrgA, scopeTestOrgB),
			want:  list + ` WHERE organization_id = ANY($1)` + order,
			args:  []driver.Value{[]string{scopeTestOrgA, scopeTestOrgB}},
			why:   "the argument is a function of the SET, so it is stable across calls and replicas",
		},
		{
			name:  "unowned rows are admitted only when asked for",
			scope: store.OrgScopeOrganizationsAndUnowned(scopeTestOrgA),
			want:  list + ` WHERE (organization_id = ANY($1) OR organization_id IS NULL)` + order,
			args:  []driver.Value{[]string{scopeTestOrgA}},
			why: "a channel written before a consumer's backfill ran has a NULL owner; whether " +
				"that means platform-level or not-yet-assigned is the consumer's call, at the call site",
		},
		{
			name:  "unowned alone selects only the unowned",
			scope: store.OrgScopeOrganizationsAndUnowned(),
			want:  list + ` WHERE organization_id IS NULL` + order,
			why:   "the legitimate 'no ids, unowned only' scope",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo, mock := newScopedChannelRepo(t)
			mock.ExpectQuery(tc.want).WithArgs(tc.args...).
				WillReturnRows(fullChannelRow(scopeTestChannelID, "ENC"))

			if _, err := repo.List(context.Background(), WithOrgScope(tc.scope)); err != nil {
				t.Fatalf("List: %v\nthis scope must render as %q — %s", err, tc.want, tc.why)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%v\n%s", err, tc.why)
			}
		})
	}
}

// TestLaterOptionWins pins what repeating the option means, so that a call site
// assembling options from more than one place has a defined answer rather than
// an emergent one.
func TestLaterOptionWins(t *testing.T) {
	repo, mock := newScopedChannelRepo(t)
	mock.ExpectQuery(`SELECT ` + channelColumns + ` FROM notification_channels` +
		` WHERE organization_id = ANY($1) ORDER BY created_at DESC`).
		WithArgs([]string{scopeTestOrgB}).
		WillReturnRows(fullChannelRow(scopeTestChannelID, "ENC"))

	_, err := repo.List(context.Background(),
		WithOrgScope(store.OrgScopeOrganizations(scopeTestOrgA)),
		WithOrgScope(store.OrgScopeOrganizations(scopeTestOrgB)))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// TestTheOrganizationColumnIsNeverRequiredOfEveryConsumer is the guard that
// keeps this capability optional at the two places it could stop being so.
//
// channelColumns is what every statement SELECTS and scans, and
// channelColumnRequirements is what VerifyChannelTable demands of every
// consumer's table at startup. Adding organization_id to either would make
// terraform-registry — which has no such column — fail a scan or fail to boot,
// which is the same defect as hard-coding the predicate, just relocated.
// ChannelTableDDL is the definition consumers apply, so shipping the column
// there would push it onto a consumer that does not want it.
func TestTheOrganizationColumnIsNeverRequiredOfEveryConsumer(t *testing.T) {
	if strings.Contains(channelColumns, ChannelOrganizationColumn) {
		t.Errorf("channelColumns selects %s. Every statement here scans that list into "+
			"NotificationChannel, so a consumer without the column fails the scan at "+
			"delivery time", ChannelOrganizationColumn)
	}
	if _, required := channelColumnRequirements[ChannelOrganizationColumn]; required {
		t.Errorf("channelColumnRequirements demands %s. VerifyChannelTable states what EVERY "+
			"consumer must have; this column is required only of the one that partitions "+
			"channels by organization, and VerifyChannelOrganizationColumn is where that "+
			"is asserted", ChannelOrganizationColumn)
	}
	if strings.Contains(ChannelTableDDL, ChannelOrganizationColumn) {
		t.Errorf("ChannelTableDDL creates %s. Consumers build their migration from this "+
			"statement, so the column would arrive in a schema that has no use for it",
			ChannelOrganizationColumn)
	}
}

// expectOrganizationColumnSchema arranges the catalogue read
// VerifyChannelOrganizationColumn performs. It does not read search_path, unlike
// VerifyChannelTable, because it is a follow-on check: the table's location has
// already been reported by the assertion a consumer runs first.
func expectOrganizationColumnSchema(mock sqlmock.Sqlmock, schema, dataType string, present bool) {
	rows := sqlmock.NewRows([]string{"nspname", "attname", "format_type", "attnotnull"}).
		AddRow(schema, "id", "uuid", true).
		AddRow(schema, "name", "text", true)
	if present {
		rows = rows.AddRow(schema, ChannelOrganizationColumn, dataType, false)
	}
	mock.ExpectQuery("pg_catalog[.]pg_attribute").WillReturnRows(rows)
}

func TestVerifyChannelOrganizationColumn_AcceptsTheShapesThePredicateCanBind(t *testing.T) {
	// Nullable is accepted deliberately: terraform-state-manager's 000033 adds
	// the column NULLABLE and only makes it NOT NULL in its final phase, so
	// asserting either state would fail a deployment that works.
	for _, dataType := range []string{"uuid", "text", "character varying(64)"} {
		t.Run(dataType, func(t *testing.T) {
			repo, mock := newChannelRepo(t)
			expectOrganizationColumnSchema(mock, "public", dataType, true)

			if err := VerifyChannelOrganizationColumn(context.Background(), repo.db); err != nil {
				t.Fatalf("%s must satisfy the tenant predicate — `= ANY($n)` binds a string "+
					"list against all of them: %v", dataType, err)
			}
		})
	}
}

func TestVerifyChannelOrganizationColumn_RejectsWhatWouldFailAtQueryTime(t *testing.T) {
	cases := []struct {
		name     string
		dataType string
		present  bool
		wantIn   string
	}{
		{
			name:    "the column the other consumer does not have",
			present: false,
			wantIn:  "has no " + ChannelOrganizationColumn + " column",
		},
		{
			name:     "a type the predicate cannot bind",
			dataType: "integer",
			present:  true,
			wantIn:   "is integer",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo, mock := newChannelRepo(t)
			expectOrganizationColumnSchema(mock, "app", tc.dataType, tc.present)

			err := VerifyChannelOrganizationColumn(context.Background(), repo.db)
			if err == nil {
				t.Fatal("VerifyChannelOrganizationColumn accepted a table WithOrgScope cannot " +
					"scope. The failure it replaces is an admin opening the channels page and " +
					"getting a Postgres error, or an empty list read as 'none configured'")
			}
			if !errors.Is(err, ErrChannelTable) {
				t.Errorf("error does not wrap ErrChannelTable: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error does not say what is wrong (%q):\n%v", tc.wantIn, err)
			}
			if !strings.Contains(err.Error(), "app."+ChannelTable) {
				t.Errorf("error does not name the resolved table, so an operator cannot tell "+
					"WHICH notification_channels was checked:\n%v", err)
			}
		})
	}
}

func TestVerifyChannelOrganizationColumn_ReportsATableThatResolvesToNothing(t *testing.T) {
	repo, mock := newChannelRepo(t)
	mock.ExpectQuery("pg_catalog[.]pg_attribute").
		WillReturnRows(sqlmock.NewRows([]string{"nspname", "attname", "format_type", "attnotnull"}))

	err := VerifyChannelOrganizationColumn(context.Background(), repo.db)
	if err == nil {
		t.Fatal("VerifyChannelOrganizationColumn accepted a name that resolves to no table")
	}
	if !strings.Contains(err.Error(), "VerifyChannelTable") {
		t.Errorf("a missing TABLE should point at the assertion that explains table ownership, "+
			"not read as a missing column:\n%v", err)
	}
}

func TestVerifyChannelOrganizationColumn_RejectsANilHandle(t *testing.T) {
	err := VerifyChannelOrganizationColumn(context.Background(), nil)
	if !errors.Is(err, ErrChannelTable) {
		t.Errorf("VerifyChannelOrganizationColumn(nil) = %v, want an ErrChannelTable", err)
	}
}

func TestVerifyChannelOrganizationColumn_PropagatesACatalogueFailure(t *testing.T) {
	repo, mock := newChannelRepo(t)
	mock.ExpectQuery("pg_catalog[.]pg_attribute").WillReturnError(errDB)

	err := VerifyChannelOrganizationColumn(context.Background(), repo.db)
	if !errors.Is(err, ErrChannelTable) || !errors.Is(err, errDB) {
		t.Errorf("a catalogue read failure must surface as both sentinels, so a caller can "+
			"tell a broken connection from a wrong schema: %v", err)
	}
}
