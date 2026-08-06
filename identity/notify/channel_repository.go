// channel_repository.go is the DAO for notification_channels: admin-configured
// delivery destinations (webhook, Slack, Microsoft Teams, or an ad-hoc email
// recipient list) for notification events, in addition to each app's own
// shared SMTP recipients list. Every consuming app's notification_channels
// table must use this exact schema: id UUID, name/type/encrypted_target TEXT,
// events JSONB, enabled BOOLEAN, last_status/last_error TEXT,
// last_sent_at/created_at/updated_at TIMESTAMPTZ.
package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

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

// Create inserts a new channel and returns it (with the target redacted).
func (r *ChannelRepository) Create(ctx context.Context, ch *NotificationChannel) (*NotificationChannel, error) {
	eventsJSON, err := json.Marshal(ch.Events)
	if err != nil {
		return nil, err
	}
	row := r.db.QueryRowContext(ctx, `
		INSERT INTO notification_channels (name, type, encrypted_target, events, enabled)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+channelColumns,
		ch.Name, ch.Type, ch.EncryptedTarget, eventsJSON, ch.Enabled)
	saved, err := scanChannel(row)
	if err != nil {
		return nil, err
	}
	saved.EncryptedTarget = "" // never expose the secret to callers
	return saved, nil
}

// List returns all channels without the encrypted target (for the admin UI).
func (r *ChannelRepository) List(ctx context.Context) ([]NotificationChannel, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+channelColumns+` FROM notification_channels ORDER BY created_at DESC`)
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
func (r *ChannelRepository) GetByID(ctx context.Context, id string) (*NotificationChannel, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+channelColumns+` FROM notification_channels WHERE id = $1`, id)
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
func (r *ChannelRepository) Update(ctx context.Context, id, name, typ string, events []string, enabled bool, encryptedTarget string) (*NotificationChannel, error) {
	eventsJSON, err := json.Marshal(events)
	if err != nil {
		return nil, err
	}
	var targetArg any
	if encryptedTarget != "" {
		targetArg = encryptedTarget
	}
	row := r.db.QueryRowContext(ctx, `
		UPDATE notification_channels
		SET name=$2, type=$3, events=$4, enabled=$5,
		    encrypted_target=COALESCE($6, encrypted_target), updated_at=now()
		WHERE id=$1
		RETURNING `+channelColumns,
		id, name, typ, eventsJSON, enabled, targetArg)
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
func (r *ChannelRepository) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM notification_channels WHERE id = $1`, id)
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
func (r *ChannelRepository) ListEnabledForEvent(ctx context.Context, eventType string) ([]NotificationChannel, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+channelColumns+`
		FROM notification_channels
		WHERE enabled AND (jsonb_array_length(events) = 0 OR events @> to_jsonb($1::text))`, eventType)
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
func (r *ChannelRepository) RecordDelivery(ctx context.Context, id, status, errMsg string, sentAt time.Time) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE notification_channels SET last_status=$2, last_error=NULLIF($3,''), last_sent_at=$4, updated_at=now() WHERE id=$1`,
		id, status, errMsg, sentAt)
	if err != nil {
		return err
	}
	return requireChannelRow(res)
}
