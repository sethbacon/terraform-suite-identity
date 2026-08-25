// channel_repository.go is the DAO for notification_channels: admin-configured
// delivery destinations (webhook, Slack, Microsoft Teams, or an ad-hoc email
// recipient list) for notification events, in addition to each app's own
// shared SMTP recipients list.
//
// The table is owned and created by the CONSUMING APP, not by this module's
// migrations. Its required shape used to be stated here as a sentence, which
// each app then re-implemented by hand and drifted from; it now lives in
// schema.go as ChannelTableDDL (the statement to apply) and
// channelColumnRequirements (what VerifyChannelTable asserts at startup), both
// executed by this package's own tests. See schema.go for the shape and for why
// no migration here creates the table.
//
// Every row-selecting statement here takes an optional ChannelQueryOption, so a
// consumer whose table carries an organization_id can restrict it to a tenant.
// The default — no options — is the unscoped statement this package has always
// emitted. channel_scope.go explains why that optionality is right here and
// wrong in identity/store.
package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity/internal/pgquote"
	"github.com/sethbacon/terraform-suite-identity/identity/store"
)

const channelColumns = `id, name, type, encrypted_target, events, enabled,
	last_status, last_error, last_sent_at, created_at, updated_at`

// ChannelRepository is the DAO for notification_channels.
type ChannelRepository struct {
	db *sql.DB
}

// NewChannelRepository constructs the repository over the app connection.
func NewChannelRepository(db *sql.DB) *ChannelRepository {
	return &ChannelRepository{db: db}
}

func scanChannel(scanner interface{ Scan(dest ...any) error }) (*NotificationChannel, error) {
	var ch NotificationChannel
	var eventsJSON []byte
	var lastStatus, lastError sql.NullString
	var lastSentAt sql.NullTime
	if err := scanner.Scan(&ch.ID, &ch.Name, &ch.Type, &ch.EncryptedTarget, &eventsJSON, &ch.Enabled,
		&lastStatus, &lastError, &lastSentAt, &ch.CreatedAt, &ch.UpdatedAt); err != nil {
		return nil, err
	}
	ch.HasTarget = ch.EncryptedTarget != ""
	if len(eventsJSON) > 0 {
		if err := json.Unmarshal(eventsJSON, &ch.Events); err != nil {
			return nil, err
		}
	}
	if ch.Events == nil {
		ch.Events = []string{}
	}
	if lastStatus.Valid {
		ch.LastStatus = &lastStatus.String
	}
	if lastError.Valid {
		ch.LastError = &lastError.String
	}
	if lastSentAt.Valid {
		ch.LastSentAt = &lastSentAt.Time
	}
	return &ch, nil
}

// marshalEvents renders the event filter for the jsonb events column.
//
// json.Marshal produces the JSON scalar `null` for a NIL slice and `[]` for an
// empty one, and the column takes whichever it is given. That distinction is
// invisible in Go -- Events is an ordinary slice field whose zero value is nil,
// so a caller that simply omits it writes the scalar -- and it is fatal on read:
// ListEnabledForEvent applies jsonb_array_length(events), which errors on a
// scalar and fails the ENTIRE statement rather than skipping the offending row.
// One channel created with nil events therefore stops every notification in the
// deployment, including the perfectly valid channels that should have matched.
//
// Normalising in one place, at the single write boundary, is what keeps this out
// of the column: there are two writers today and the defect class is precisely
// "one of them learned the rule and its sibling did not". scanChannel already
// normalises nil to []string{} coming back, so this makes the two directions
// agree rather than introducing a new convention.
func marshalEvents(events []string) ([]byte, error) {
	if events == nil {
		events = []string{}
	}
	return json.Marshal(events)
}

// Create inserts a new channel and returns it (with the target redacted).
//
// It takes no ChannelQueryOption -- a scope is a predicate over rows that already
// exist, and an INSERT selects none -- but it does take ChannelWriteOptions,
// which supply VALUES rather than predicates. WithOwningOrganization is the one
// that matters for a partitioned consumer, and channel_owner.go explains why the
// column DEFAULT this used to defer to is a backfill answer rather than a tenant
// answer.
//
// With no options the statement is byte-for-byte the one this package has always
// emitted, so a consumer that does not partition keeps its DEFAULT.
func (r *ChannelRepository) Create(ctx context.Context, ch *NotificationChannel, opts ...ChannelWriteOption) (*NotificationChannel, error) {
	eventsJSON, err := marshalEvents(ch.Events)
	if err != nil {
		return nil, err
	}
	write, err := newChannelWrite(opts)
	if err != nil {
		return nil, err
	}
	names, values := write.columns()
	columns := "name, type, encrypted_target, events, enabled"
	placeholders := "$1, $2, $3, $4, $5"
	args := []any{ch.Name, ch.Type, ch.EncryptedTarget, eventsJSON, ch.Enabled}
	for i, name := range names {
		// pgquote.Identifier per this module's policy: an identifier is never
		// parameterisable, so it is interpolated, so it is quoted in one place
		// rather than open-coded per call site (see identity/internal/pgquote).
		// The names are already a closed literal set -- channel_owner_columns_test.go
		// guards that -- so this is the second lock, not the only one.
		columns += ", " + pgquote.Identifier(name)
		// ::uuid so the driver's text parameter lands in a uuid column. The
		// placeholder number is derived, never interpolated from caller input --
		// `name` comes from this package's own option constructors.
		placeholders += fmt.Sprintf(", $%d::uuid", len(args)+1)
		args = append(args, values[i])
	}
	row := r.db.QueryRowContext(ctx, `
		INSERT INTO notification_channels (`+columns+`)
		VALUES (`+placeholders+`)
		RETURNING `+channelColumns,
		args...)
	saved, err := scanChannel(row)
	if err != nil {
		return nil, err
	}
	saved.EncryptedTarget = "" // never expose the secret to callers
	return saved, nil
}

// List returns all channels without the encrypted target (for the admin UI),
// restricted to the organizations of any WithOrgScope option supplied.
func (r *ChannelRepository) List(ctx context.Context, opts ...ChannelQueryOption) ([]NotificationChannel, error) {
	query, args := newChannelFilter(opts).splice(
		`SELECT `+channelColumns+` FROM notification_channels`, " WHERE ", nil)
	query += ` ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NotificationChannel{}
	for rows.Next() {
		ch, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		ch.EncryptedTarget = ""
		out = append(out, *ch)
	}
	return out, rows.Err()
}

// GetByID returns a channel including its encrypted target (for decryption by
// the notifier / test endpoint).
//
// Returns an error wrapping store.ErrNotFound when no channel has that ID. This
// DAO reports not-found with the identity store's sentinel rather than one of
// its own: a consuming app wires both packages and must not have to remember
// which of two spellings of "not found" a given repository speaks.
// A channel outside a supplied WithOrgScope is reported as not-found rather than
// as forbidden, which is the same answer identity/store's scoped by-id reads
// give: distinguishing the two would confirm the existence of another tenant's
// channel to a caller who may not read it.
func (r *ChannelRepository) GetByID(ctx context.Context, id string, opts ...ChannelQueryOption) (*NotificationChannel, error) {
	query, args := newChannelFilter(opts).splice(
		`SELECT `+channelColumns+` FROM notification_channels WHERE id = $1`, " AND ", []any{id})
	row := r.db.QueryRowContext(ctx, query, args...)
	ch, err := scanChannel(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("notification channel by id: %w", store.ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	return ch, nil
}

// Update replaces the mutable fields. When encryptedTarget is empty the
// existing target is kept (so editing a channel without re-entering the
// secret is allowed).
//
// Returns an error wrapping store.ErrNotFound when the channel does not exist —
// the RETURNING clause yields no row, which is the same "matched nothing" the
// by-id mutators in identity/store report.
// A WithOrgScope option constrains WHICH row the id may match, so a caller
// scoped to one organization cannot edit another's channel. It is applied for
// the reason org_scope.go gives for applying the predicate to every access axis
// of a table at once: a boundary that a list read enforces and a by-id mutation
// does not is not a boundary, and the defect class it closes is exactly "one
// query learned the predicate and its siblings did not".
func (r *ChannelRepository) Update(ctx context.Context, id, name, typ string, events []string, enabled bool, encryptedTarget string, opts ...ChannelQueryOption) (*NotificationChannel, error) {
	eventsJSON, err := marshalEvents(events)
	if err != nil {
		return nil, err
	}
	var targetArg any
	if encryptedTarget != "" {
		targetArg = encryptedTarget
	}
	query, args := newChannelFilter(opts).splice(`
		UPDATE notification_channels
		SET name=$2, type=$3, events=$4, enabled=$5,
		    encrypted_target=COALESCE($6, encrypted_target), updated_at=now()
		WHERE id=$1`, " AND ", []any{id, name, typ, eventsJSON, enabled, targetArg})
	query += `
		RETURNING ` + channelColumns
	row := r.db.QueryRowContext(ctx, query, args...)
	ch, err := scanChannel(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("notification channel by id: %w", store.ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	ch.EncryptedTarget = ""
	return ch, nil
}

// Delete removes a channel.
//
// Returns an error wrapping store.ErrNotFound when no channel has that ID, so
// an admin UI cannot report a channel deleted that it did not delete.
// A WithOrgScope option constrains which row the id may match; a delete outside
// the scope matches nothing and so reports store.ErrNotFound, which is both the
// non-disclosing answer and the true one.
func (r *ChannelRepository) Delete(ctx context.Context, id string, opts ...ChannelQueryOption) error {
	query, args := newChannelFilter(opts).splice(
		`DELETE FROM notification_channels WHERE id = $1`, " AND ", []any{id})
	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	return requireChannelRow(res)
}

// requireChannelRow turns a by-id mutation that matched no notification_channels
// row into store.ErrNotFound, mirroring identity/store's requireRow (which is
// unexported and so cannot be shared across the package boundary).
func requireChannelRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to read rows affected for notification channel by id: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("notification channel by id: %w", store.ErrNotFound)
	}
	return nil
}

// ListEnabledForEvent returns enabled channels subscribed to eventType (a
// channel with no events subscribes to all). Includes the encrypted target
// for sending.
//
// A WithOrgScope option restricts delivery to that tenant's channels. An event
// raised inside one organization must not fan out to another organization's
// webhook, so a consumer that partitions this table scopes the SEND path too and
// not only the admin UI that lists it.
func (r *ChannelRepository) ListEnabledForEvent(ctx context.Context, eventType string, opts ...ChannelQueryOption) ([]NotificationChannel, error) {
	query, args := newChannelFilter(opts).splice(`SELECT `+channelColumns+`
		FROM notification_channels
		WHERE enabled AND (jsonb_array_length(events) = 0 OR events @> to_jsonb($1::text))`, " AND ", []any{eventType})
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NotificationChannel{}
	for rows.Next() {
		ch, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *ch)
	}
	return out, rows.Err()
}

// RecordDelivery stamps the outcome of the most recent send attempt.
//
// Returns an error wrapping store.ErrNotFound when the channel was deleted
// between the send and this write. Notifier.record logs that (it is the only
// caller and delivery has already happened, so there is nothing to roll back)
// rather than dropping it, which is exactly the difference between a delivery
// record that is missing for a known reason and one that is silently absent.
// A WithOrgScope option constrains which row the id may match, keeping this
// statement on the same axis as the read that selected the channel to send to.
func (r *ChannelRepository) RecordDelivery(ctx context.Context, id, status, errMsg string, sentAt time.Time, opts ...ChannelQueryOption) error {
	query, args := newChannelFilter(opts).splice(
		`UPDATE notification_channels SET last_status=$2, last_error=NULLIF($3,''), last_sent_at=$4, updated_at=now() WHERE id=$1`,
		" AND ", []any{id, status, errMsg, sentAt})
	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	return requireChannelRow(res)
}
