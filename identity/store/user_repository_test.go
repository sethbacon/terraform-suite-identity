package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

var errDB = errors.New("db error")

var userCols = []string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}

func sampleUserRow() *sqlmock.Rows {
	return sqlmock.NewRows(userCols).
		AddRow("user-1", "alice@example.com", "Alice", nil, time.Now(), time.Now())
}

func emptyUserRow() *sqlmock.Rows {
	return sqlmock.NewRows(userCols)
}

func newUserRepo(t *testing.T) (*UserRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewUserRepository(db), mock
}

// ---------------------------------------------------------------------------
// GetUserByID
// ---------------------------------------------------------------------------

func TestGetUserByID_Found(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WithArgs("user-1").
		WillReturnRows(sampleUserRow())

	user, err := repo.GetUserByID(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
	if user.ID != "user-1" {
		t.Errorf("ID = %s, want user-1", user.ID)
	}
}

func TestGetUserByID_NotFound(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WithArgs("missing").
		WillReturnRows(emptyUserRow())

	user, err := repo.GetUserByID(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if user != nil {
		t.Errorf("expected nil user for not found, got %v", user)
	}
}

func TestGetUserByID_DBError(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WithArgs("user-1").
		WillReturnError(errDB)

	_, err := repo.GetUserByID(context.Background(), "user-1")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetUserByEmail
// ---------------------------------------------------------------------------

func TestGetUserByEmail_Found(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("alice@example.com").
		WillReturnRows(sampleUserRow())

	user, err := repo.GetUserByEmail(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
}

func TestGetUserByEmail_NotFound(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("nobody@example.com").
		WillReturnRows(emptyUserRow())

	user, err := repo.GetUserByEmail(context.Background(), "nobody@example.com")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if user != nil {
		t.Errorf("expected nil user, got %v", user)
	}
}

// ---------------------------------------------------------------------------
// GetUserByOIDCSub
// ---------------------------------------------------------------------------

func TestGetUserByOIDCSub_Found(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-123").
		WillReturnRows(sampleUserRow())

	user, err := repo.GetUserByOIDCSub(context.Background(), "sub-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
}

func TestGetUserByOIDCSub_NotFound(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-missing").
		WillReturnRows(emptyUserRow())

	user, err := repo.GetUserByOIDCSub(context.Background(), "sub-missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if user != nil {
		t.Error("expected nil, got non-nil")
	}
}

// ---------------------------------------------------------------------------
// CreateUser
// ---------------------------------------------------------------------------

func TestCreateUser_Success(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectExec("INSERT INTO users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	user := &models.User{Email: "bob@example.com", Name: "Bob"}
	if err := repo.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.ID == "" {
		t.Error("expected ID to be set")
	}
}

func TestCreateUser_DBError(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectExec("INSERT INTO users").
		WillReturnError(errDB)

	user := &models.User{Email: "bob@example.com", Name: "Bob"}
	if err := repo.CreateUser(context.Background(), user); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// UpdateUser
// ---------------------------------------------------------------------------

func TestUpdateUser_Success(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectExec("UPDATE users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	user := &models.User{ID: "user-1", Email: "alice@example.com", Name: "Alice Updated"}
	if err := repo.UpdateUser(context.Background(), user); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateUser_DBError(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectExec("UPDATE users").
		WillReturnError(errDB)

	user := &models.User{ID: "user-1", Email: "alice@example.com", Name: "Alice"}
	if err := repo.UpdateUser(context.Background(), user); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// DeleteUser
// ---------------------------------------------------------------------------

func TestDeleteUser_Success(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectExec("DELETE FROM users").
		WithArgs("user-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.DeleteUser(context.Background(), "user-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteUser_DBError(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectExec("DELETE FROM users").
		WillReturnError(errDB)

	if err := repo.DeleteUser(context.Background(), "user-1"); err == nil {
		t.Error("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// ListUsers
// ---------------------------------------------------------------------------

func TestListUsers_Success(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT COUNT.*FROM users").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM users.*ORDER BY").
		WillReturnRows(sampleUserRow())

	users, total, err := repo.ListUsers(context.Background(), 20, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(users) != 1 {
		t.Errorf("len(users) = %d, want 1", len(users))
	}
}

func TestListUsers_CountError(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT COUNT.*FROM users").
		WillReturnError(errDB)

	_, _, err := repo.ListUsers(context.Background(), 20, 0)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestListUsers_Empty(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT COUNT.*FROM users").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT.*FROM users.*ORDER BY").
		WillReturnRows(emptyUserRow())

	users, total, err := repo.ListUsers(context.Background(), 20, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 0 {
		t.Errorf("total = %d, want 0", total)
	}
	if len(users) != 0 {
		t.Errorf("len(users) = %d, want 0", len(users))
	}
}

// ---------------------------------------------------------------------------
// List (simple paginated list)
// ---------------------------------------------------------------------------

func TestList_Success(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*ORDER BY").
		WillReturnRows(sampleUserRow())

	users, err := repo.List(context.Background(), 20, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("len(users) = %d, want 1", len(users))
	}
}

// ---------------------------------------------------------------------------
// Count
// ---------------------------------------------------------------------------

func TestCount_Success(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT COUNT.*FROM users").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(42))

	count, err := repo.Count(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 42 {
		t.Errorf("count = %d, want 42", count)
	}
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

func TestSearch_Success(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*WHERE.*ILIKE").
		WillReturnRows(sampleUserRow())

	users, err := repo.Search(context.Background(), "alice", 20, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("len(users) = %d, want 1", len(users))
	}
}

func TestSearch_EscapesLikeMetacharacters(t *testing.T) {
	repo, mock := newUserRepo(t)

	// A term containing LIKE wildcards must be bound with the metacharacters
	// escaped so they match literally instead of widening the pattern.
	mock.ExpectQuery("SELECT.*FROM users.*WHERE.*ILIKE").
		WithArgs(`%50\%\_off%`, 20, 0).
		WillReturnRows(emptyUserRow())

	if _, err := repo.Search(context.Background(), "50%_off", 20, 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestSearch_Empty(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*WHERE.*ILIKE").
		WillReturnRows(emptyUserRow())

	users, err := repo.Search(context.Background(), "nobody", 20, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("len(users) = %d, want 0", len(users))
	}
}

// ---------------------------------------------------------------------------
// GetOrCreateUserFromOIDC
// ---------------------------------------------------------------------------

func TestGetOrCreateUserFromOIDC_ExistingUser_NoChange(t *testing.T) {
	repo, mock := newUserRepo(t)

	// GetByOIDCSub finds user with matching email/name
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-123").
		WillReturnRows(sampleUserRow()) // email=alice@example.com, name=Alice

	user, err := repo.GetOrCreateUserFromOIDC(context.Background(), "sub-123", "alice@example.com", "Alice", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
}

func TestGetOrCreateUserFromOIDC_ExistingUser_UpdateNeeded(t *testing.T) {
	repo, mock := newUserRepo(t)

	// GetByOIDCSub finds user with different email
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-123").
		WillReturnRows(sampleUserRow()) // email=alice@example.com
	// UpdateUser called because email changed
	mock.ExpectExec("UPDATE users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	user, err := repo.GetOrCreateUserFromOIDC(context.Background(), "sub-123", "alice_new@example.com", "Alice", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
}

func TestGetOrCreateUserFromOIDC_NewUser(t *testing.T) {
	repo, mock := newUserRepo(t)

	// GetByOIDCSub finds no user
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-new").
		WillReturnRows(emptyUserRow())
	// Email lookup also finds no user (no pre-provisioned user)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("new@example.com").
		WillReturnRows(emptyUserRow())
	// CreateUser
	mock.ExpectExec("INSERT INTO users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	user, err := repo.GetOrCreateUserFromOIDC(context.Background(), "sub-new", "new@example.com", "New User", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
}

// TestGetOrCreateUserFromOIDC_InsertRowsAffectedUnreadable pins that the INSERT's
// RowsAffected error is NOT discarded. Reading it as zero would send a
// successful creation down the lost-the-race re-read path, where it would
// either return another request's row or fail with a misleading "conflicting
// row not found on re-read".
func TestGetOrCreateUserFromOIDC_InsertRowsAffectedUnreadable(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-new").
		WillReturnRows(emptyUserRow())
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("new@example.com").
		WillReturnRows(emptyUserRow())
	// A driver that cannot report how many rows the INSERT affected.
	mock.ExpectExec("INSERT INTO users").
		WillReturnResult(sqlmock.NewErrorResult(errDB))

	user, err := repo.GetOrCreateUserFromOIDC(context.Background(), "sub-new", "new@example.com", "New User", true)
	if err == nil {
		t.Fatal("an unreadable RowsAffected was reported as a successful login")
	}
	if !strings.Contains(err.Error(), "rows affected") {
		t.Errorf("error = %q, want it to name the unreadable rows-affected result", err)
	}
	if user != nil {
		t.Errorf("expected nil user alongside the error, got %v", user)
	}
}

func TestGetOrCreateUserFromOIDC_NewUser_ConcurrentCreateLostViaZeroRowsAffected(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-race").
		WillReturnRows(emptyUserRow())
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("race@example.com").
		WillReturnRows(emptyUserRow())
	// A concurrent goroutine already created this identity: ON CONFLICT (oidc_sub)
	// DO NOTHING suppresses our insert, so RowsAffected is 0 (no error).
	mock.ExpectExec("INSERT INTO users").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// The fallback re-read finds the concurrent winner's row.
	winnerSub := "sub-race"
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-race").
		WillReturnRows(sqlmock.NewRows(userCols).
			AddRow("winner-id", "race@example.com", "Race Winner", &winnerSub, time.Now(), time.Now()))

	user, err := repo.GetOrCreateUserFromOIDC(context.Background(), "sub-race", "race@example.com", "New User", true)
	if err != nil {
		t.Fatalf("expected the race to resolve without error, got: %v", err)
	}
	if user == nil || user.ID != "winner-id" {
		t.Fatalf("expected the concurrent winner's row, got %+v", user)
	}
}

func TestGetOrCreateUserFromOIDC_NewUser_ConcurrentCreateLostViaUniqueViolation(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-race2").
		WillReturnRows(emptyUserRow())
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("race2@example.com").
		WillReturnRows(emptyUserRow())
	// The concurrent winner's row was already visible to a DIFFERENT unique index
	// (e.g. email) before the oidc_sub arbiter, surfacing as a raw unique-violation
	// rather than a suppressed (0 rows affected) conflict. Must be treated the
	// same way: fall back to the winner's row instead of propagating the error.
	mock.ExpectExec("INSERT INTO users").
		WillReturnError(&pq.Error{Code: "23505", Message: "duplicate key value violates unique constraint"})
	winnerSub := "sub-race2"
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-race2").
		WillReturnRows(sqlmock.NewRows(userCols).
			AddRow("winner-id-2", "race2@example.com", "Race Winner", &winnerSub, time.Now(), time.Now()))

	user, err := repo.GetOrCreateUserFromOIDC(context.Background(), "sub-race2", "race2@example.com", "New User", true)
	if err != nil {
		t.Fatalf("expected the race to resolve without error, got: %v", err)
	}
	if user == nil || user.ID != "winner-id-2" {
		t.Fatalf("expected the concurrent winner's row, got %+v", user)
	}
}

func TestGetOrCreateUserFromOIDC_NewUser_NonUniqueViolationErrorPropagates(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-err").
		WillReturnRows(emptyUserRow())
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("err@example.com").
		WillReturnRows(emptyUserRow())
	// A non-unique-violation error (e.g. connection loss) must propagate as-is,
	// not be swallowed by the race-recovery fallback.
	mock.ExpectExec("INSERT INTO users").
		WillReturnError(errDB)

	_, err := repo.GetOrCreateUserFromOIDC(context.Background(), "sub-err", "err@example.com", "New User", true)
	if err == nil {
		t.Fatal("expected the non-unique-violation error to propagate")
	}
	if mockErr := mock.ExpectationsWereMet(); mockErr != nil {
		t.Errorf("unexpected DB calls (a re-read would indicate the race-fallback fired incorrectly): %v", mockErr)
	}
}

func TestGetOrCreateUserFromOIDC_LinksPreProvisionedUser(t *testing.T) {
	repo, mock := newUserRepo(t)

	// sub lookup misses
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-new").
		WillReturnRows(emptyUserRow())
	// email lookup finds a pre-provisioned user with a NULL oidc_sub
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("alice@example.com").
		WillReturnRows(sampleUserRow()) // oidc_sub is nil
	// linking updates the row
	mock.ExpectExec("UPDATE users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	user, err := repo.GetOrCreateUserFromOIDC(context.Background(), "sub-new", "alice@example.com", "Alice", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil || user.OIDCSub == nil || *user.OIDCSub != "sub-new" {
		t.Fatalf("expected oidc_sub to be linked to sub-new, got %+v", user)
	}
}

func TestGetOrCreateUserFromOIDC_PreProvisionedLink_LosesRaceToSameSub(t *testing.T) {
	repo, mock := newUserRepo(t)

	// sub lookup misses
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-race").
		WillReturnRows(emptyUserRow())
	// email lookup finds a pre-provisioned user with a NULL oidc_sub
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("alice@example.com").
		WillReturnRows(sampleUserRow())
	// The compare-and-set link UPDATE (WHERE ... AND oidc_sub IS NULL) affects
	// zero rows: a concurrent request already linked this row first.
	mock.ExpectExec("UPDATE users").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// The re-read finds the concurrent winner already linked to the SAME sub
	// (e.g. the identical login retried, or double-tab) — this must succeed,
	// not error.
	winnerSub := "sub-race"
	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows(userCols).
			AddRow("user-1", "alice@example.com", "Alice", &winnerSub, time.Now(), time.Now()))

	user, err := repo.GetOrCreateUserFromOIDC(context.Background(), "sub-race", "alice@example.com", "Alice", true)
	if err != nil {
		t.Fatalf("expected the race to resolve without error, got: %v", err)
	}
	if user == nil || user.OIDCSub == nil || *user.OIDCSub != "sub-race" {
		t.Fatalf("expected the concurrent winner's row linked to sub-race, got %+v", user)
	}
}

func TestGetOrCreateUserFromOIDC_PreProvisionedLink_LosesRaceToDifferentSub(t *testing.T) {
	repo, mock := newUserRepo(t)

	// sub lookup misses
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-loser").
		WillReturnRows(emptyUserRow())
	// email lookup finds a pre-provisioned user with a NULL oidc_sub
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("alice@example.com").
		WillReturnRows(sampleUserRow())
	// The compare-and-set link UPDATE affects zero rows: a DIFFERENT concurrent
	// identity won the race first.
	mock.ExpectExec("UPDATE users").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// The re-read finds the row now linked to a DIFFERENT sub than ours — this
	// must be refused, exactly like the non-racing RefusesRelinkDifferentSub case.
	winnerSub := "sub-winner"
	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows(userCols).
			AddRow("user-1", "alice@example.com", "Alice", &winnerSub, time.Now(), time.Now()))

	_, err := repo.GetOrCreateUserFromOIDC(context.Background(), "sub-loser", "alice@example.com", "Alice", true)
	if err == nil {
		t.Fatal("expected account linking to be refused when the race is lost to a different oidc_sub")
	}
}

func TestGetOrCreateUserFromOIDC_PreProvisionedLink_RaceReReadError(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-x").
		WillReturnRows(emptyUserRow())
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("alice@example.com").
		WillReturnRows(sampleUserRow())
	mock.ExpectExec("UPDATE users").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// The re-read itself fails (e.g. connection loss) — must propagate, not panic.
	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WithArgs("user-1").
		WillReturnError(errDB)

	_, err := repo.GetOrCreateUserFromOIDC(context.Background(), "sub-x", "alice@example.com", "Alice", true)
	if err == nil {
		t.Fatal("expected the re-read error to propagate")
	}
}

func TestGetOrCreateUserFromOIDC_RefusesRelinkDifferentSub(t *testing.T) {
	repo, mock := newUserRepo(t)

	// sub lookup misses (attacker presents a new sub)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("attacker-sub").
		WillReturnRows(emptyUserRow())
	// email lookup finds an account ALREADY linked to a different, established sub
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("alice@example.com").
		WillReturnRows(sqlmock.NewRows(userCols).
			AddRow("user-1", "alice@example.com", "Alice", "established-sub", time.Now(), time.Now()))
	// No UPDATE is expected: re-pointing the sub must be refused.

	_, err := repo.GetOrCreateUserFromOIDC(context.Background(), "attacker-sub", "alice@example.com", "Alice", true)
	if err == nil {
		t.Fatal("expected account linking to be refused for a different established oidc_sub")
	}
	if mockErr := mock.ExpectationsWereMet(); mockErr != nil {
		t.Errorf("unexpected DB calls (an UPDATE would indicate a takeover): %v", mockErr)
	}
}

func TestGetOrCreateUserFromOIDC_RefusesUnverifiedPreProvisionedLink(t *testing.T) {
	repo, mock := newUserRepo(t)

	// sub lookup misses
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-new").
		WillReturnRows(emptyUserRow())
	// email matches a pre-provisioned (NULL oidc_sub) account
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("alice@example.com").
		WillReturnRows(sampleUserRow())
	// No UPDATE expected: an unverified email must not link the account.

	_, err := repo.GetOrCreateUserFromOIDC(context.Background(), "sub-new", "alice@example.com", "Alice", false)
	if err == nil {
		t.Fatal("expected linking to be refused for an unverified email")
	}
	if mockErr := mock.ExpectationsWereMet(); mockErr != nil {
		t.Errorf("unexpected DB calls (an UPDATE would link an unverified email): %v", mockErr)
	}
}

func TestGetOrCreateUserFromOIDC_RefusesUnverifiedNewUser(t *testing.T) {
	repo, mock := newUserRepo(t)

	// sub lookup misses
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-new").
		WillReturnRows(emptyUserRow())
	// no existing account with this email
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("new@example.com").
		WillReturnRows(emptyUserRow())
	// No INSERT expected: an unverified email must not create an account.

	_, err := repo.GetOrCreateUserFromOIDC(context.Background(), "sub-new", "new@example.com", "New User", false)
	if err == nil {
		t.Fatal("expected creation to be refused for an unverified email")
	}
	if mockErr := mock.ExpectationsWereMet(); mockErr != nil {
		t.Errorf("unexpected DB calls (an INSERT would create an account for an unverified email): %v", mockErr)
	}
}

// ---------------------------------------------------------------------------
// GetUserWithOrgRoles
// ---------------------------------------------------------------------------

func TestGetUserWithOrgRoles_NotFound(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WithArgs("missing").
		WillReturnRows(emptyUserRow())

	result, err := repo.GetUserWithOrgRoles(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if result != nil {
		t.Error("expected nil for not found user")
	}
}

func TestGetUserWithOrgRoles_Success_NoMemberships(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WithArgs("user-1").
		WillReturnRows(sampleUserRow())
	// Memberships query returns empty
	membCols := []string{
		"organization_id", "organization_name", "role_template_id", "created_at",
		"role_template_name", "role_template_display_name", "role_template_scopes",
	}
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows(membCols))

	result, err := repo.GetUserWithOrgRoles(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if len(result.Memberships) != 0 {
		t.Errorf("len(memberships) = %d, want 0", len(result.Memberships))
	}
}

func TestGetUserWithOrgRoles_DBError(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WithArgs("user-err").
		WillReturnError(errDB)

	result, err := repo.GetUserWithOrgRoles(context.Background(), "user-err")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if result != nil {
		t.Error("expected nil result on error")
	}
}

func TestGetUserWithOrgRoles_QueryError(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WithArgs("user-1").
		WillReturnRows(sampleUserRow())
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WithArgs("user-1").
		WillReturnError(errDB)

	result, err := repo.GetUserWithOrgRoles(context.Background(), "user-1")
	if err == nil {
		t.Fatal("expected error from memberships query, got nil")
	}
	if result != nil {
		t.Error("expected nil result on query error")
	}
}

func TestGetUserWithOrgRoles_WithMemberships(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WithArgs("user-1").
		WillReturnRows(sampleUserRow())

	membCols := []string{
		"organization_id", "organization_name", "role_template_id", "created_at",
		"role_template_name", "role_template_display_name", "role_template_scopes",
	}
	rtID := "rt-1"
	rtName := "admin"
	rtDisplay := "Admin"
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN organizations").
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows(membCols).AddRow(
			"org-1", "MyOrg", &rtID, time.Now(), &rtName, &rtDisplay,
			[]byte(`["modules:read","modules:write"]`),
		))

	result, err := repo.GetUserWithOrgRoles(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if len(result.Memberships) != 1 {
		t.Errorf("len(memberships) = %d, want 1", len(result.Memberships))
	}
	if len(result.Memberships[0].RoleTemplateScopes) != 2 {
		t.Errorf("len(scopes) = %d, want 2", len(result.Memberships[0].RoleTemplateScopes))
	}
}

// ---------------------------------------------------------------------------
// Create / Update / Delete delegate aliases
// ---------------------------------------------------------------------------

func TestCreate_Delegate(t *testing.T) {
	repo, mock := newUserRepo(t)
	user := &models.User{ID: "user-1", Email: "a@b.com", Name: "Alice"}
	mock.ExpectExec("INSERT INTO users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Create(context.Background(), user); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdate_Delegate(t *testing.T) {
	repo, mock := newUserRepo(t)
	user := &models.User{ID: "user-1", Email: "a@b.com", Name: "Alice"}
	mock.ExpectExec("UPDATE users SET").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Update(context.Background(), user); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDelete_Delegate(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectExec("DELETE FROM users WHERE id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.Delete(context.Background(), "user-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetOrCreateUserByOIDC (alias for GetOrCreateUserFromOIDC)
// ---------------------------------------------------------------------------

func TestGetOrCreateUserByOIDC_ExistingUser(t *testing.T) {
	repo, mock := newUserRepo(t)
	// GetUserByOIDCSub returns existing user
	mock.ExpectQuery("SELECT.*FROM users WHERE oidc_sub").
		WithArgs("sub-123").
		WillReturnRows(sampleUserRow())

	u, err := repo.GetOrCreateUserByOIDC(context.Background(), "sub-123", "alice@example.com", "Alice", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u == nil {
		t.Fatal("expected user, got nil")
	}
}

func TestGetOrCreateUserByOIDC_ExistingUserUpdateNeeded(t *testing.T) {
	repo, mock := newUserRepo(t)
	// Return user with different name
	oidcSub := "sub-123"
	mock.ExpectQuery("SELECT.*FROM users WHERE oidc_sub").
		WithArgs("sub-123").
		WillReturnRows(sqlmock.NewRows(userCols).
			AddRow("user-1", "old@example.com", "OldName", &oidcSub, time.Now(), time.Now()))
	// UpdateUser called because email/name differ
	mock.ExpectExec("UPDATE users SET").
		WillReturnResult(sqlmock.NewResult(1, 1))

	u, err := repo.GetOrCreateUserByOIDC(context.Background(), "sub-123", "new@example.com", "NewName", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u == nil {
		t.Fatal("expected user, got nil")
	}
}

func TestGetOrCreateUserByOIDC_NewUser(t *testing.T) {
	repo, mock := newUserRepo(t)
	// GetUserByOIDCSub returns no rows
	mock.ExpectQuery("SELECT.*FROM users WHERE oidc_sub").
		WillReturnRows(sqlmock.NewRows(userCols))
	// Email lookup also finds no user (no pre-provisioned user)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("new@example.com").
		WillReturnRows(sqlmock.NewRows(userCols))
	// CreateUser
	mock.ExpectExec("INSERT INTO users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	u, err := repo.GetOrCreateUserByOIDC(context.Background(), "sub-new", "new@example.com", "New User", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u == nil {
		t.Fatal("expected user, got nil")
	}
}

func TestGetOrCreateUserByOIDC_OIDCLookupError(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT.*FROM users WHERE oidc_sub").
		WillReturnError(errDB)

	_, err := repo.GetOrCreateUserByOIDC(context.Background(), "sub-123", "a@b.com", "Alice", true)
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// ListUsersWithRoles (deprecated alias for ListUsers)
// ---------------------------------------------------------------------------

func TestListUsersWithRoles_Success(t *testing.T) {
	repo, mock := newUserRepo(t)
	mock.ExpectQuery("SELECT COUNT.*FROM users").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM users").
		WillReturnRows(sampleUserRow())

	users, total, err := repo.ListUsersWithRoles(context.Background(), 20, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(users) != 1 {
		t.Errorf("len = %d, want 1", len(users))
	}
}

// ---------------------------------------------------------------------------
// GetOrCreateUserFromOIDC — email-match path
// ---------------------------------------------------------------------------

func TestGetOrCreateUserFromOIDC_EmailMatch(t *testing.T) {
	repo, mock := newUserRepo(t)

	// GetByOIDCSub finds no user
	mock.ExpectQuery("SELECT.*FROM users.*WHERE oidc_sub").
		WithArgs("sub-new").
		WillReturnRows(emptyUserRow())

	// GetByEmail finds pre-provisioned user
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("alice@example.com").
		WillReturnRows(sampleUserRow())

	// UpdateUser links the OIDC sub
	mock.ExpectExec("UPDATE users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	user, err := repo.GetOrCreateUserFromOIDC(context.Background(), "sub-new", "alice@example.com", "Alice Updated", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
}

// ---------------------------------------------------------------------------
// ListUsersWithMemberships / SearchWithMemberships (N+1 elimination)
// ---------------------------------------------------------------------------

// bulkMembershipCols matches the SELECT produced by loadMembershipsForUsers.
var bulkMembershipCols = []string{
	"user_id", "organization_id", "organization_name", "role_template_id", "created_at",
	"role_template_name", "role_template_display_name", "role_template_scopes",
}

func emptyBulkMembershipRowsRepo() *sqlmock.Rows {
	return sqlmock.NewRows(bulkMembershipCols)
}

func TestListUsersWithMemberships_Success(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT COUNT.*FROM users").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM users.*ORDER BY").
		WillReturnRows(sampleUserRow())
	// Bulk membership query for user-1
	mock.ExpectQuery("ANY").
		WillReturnRows(emptyBulkMembershipRowsRepo())

	result, total, err := repo.ListUsersWithMemberships(context.Background(), 20, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(result) != 1 {
		t.Fatalf("len(result) = %d, want 1", len(result))
	}
	if result[0].User.ID != "user-1" {
		t.Errorf("user ID = %q, want %q", result[0].User.ID, "user-1")
	}
	// Memberships should be an empty (non-nil) slice, not nil
	if result[0].Memberships == nil {
		t.Error("Memberships should be a non-nil empty slice when there are no memberships")
	}
}

func TestListUsersWithMemberships_WithMembership(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT COUNT.*FROM users").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM users.*ORDER BY").
		WillReturnRows(sampleUserRow())

	// Return one membership row for user-1
	memberRows := sqlmock.NewRows(bulkMembershipCols).AddRow(
		"user-1", "org-1", "Acme Corp", "rt-1", time.Now(),
		"admin", "Administrator", []byte(`["admin","users:read"]`),
	)
	mock.ExpectQuery("ANY").WillReturnRows(memberRows)

	result, _, err := repo.ListUsersWithMemberships(context.Background(), 20, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result[0].Memberships) != 1 {
		t.Fatalf("memberships = %d, want 1", len(result[0].Memberships))
	}
	m := result[0].Memberships[0]
	if m.OrganizationName != "Acme Corp" {
		t.Errorf("org name = %q, want %q", m.OrganizationName, "Acme Corp")
	}
	if len(m.RoleTemplateScopes) != 2 {
		t.Errorf("scopes len = %d, want 2", len(m.RoleTemplateScopes))
	}
}

func TestListUsersWithMemberships_Empty(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT COUNT.*FROM users").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT.*FROM users.*ORDER BY").
		WillReturnRows(emptyUserRow())
	// No users → no bulk membership query should be issued

	result, total, err := repo.ListUsersWithMemberships(context.Background(), 20, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 0 || len(result) != 0 {
		t.Errorf("expected empty result, got total=%d len=%d", total, len(result))
	}
}

func TestListUsersWithMemberships_MembershipDBError(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT COUNT.*FROM users").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM users.*ORDER BY").
		WillReturnRows(sampleUserRow())
	mock.ExpectQuery("ANY").WillReturnError(errDB)

	_, _, err := repo.ListUsersWithMemberships(context.Background(), 20, 0)
	if err == nil {
		t.Error("expected error from membership query, got nil")
	}
}

func TestSearchWithMemberships_Success(t *testing.T) {
	repo, mock := newUserRepo(t)

	mock.ExpectQuery("SELECT.*FROM users.*ILIKE").
		WillReturnRows(sampleUserRow())
	mock.ExpectQuery("ANY").
		WillReturnRows(emptyBulkMembershipRowsRepo())

	result, err := repo.SearchWithMemberships(context.Background(), "alice", 20, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("len(result) = %d, want 1", len(result))
	}
	if result[0].Memberships == nil {
		t.Error("Memberships should be a non-nil empty slice")
	}
}
