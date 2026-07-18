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
	"time"
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
// the notifier / test endpoint). Returns (nil, nil) when not found.
func (r *ChannelRepository) GetByID(ctx context.Context, id string) (*NotificationChannel, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+channelColumns+` FROM notification_channels WHERE id = $1`, id)
	ch, err := scanChannel(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ch, nil
}

// Update replaces the mutable fields. When encryptedTarget is empty the
// existing target is kept (so editing a channel without re-entering the
// secret is allowed). Returns (nil, nil) when the channel does not exist.
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
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ch.EncryptedTarget = ""
	return ch, nil
}

// Delete removes a channel.
func (r *ChannelRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM notification_channels WHERE id = $1`, id)
	return err
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
func (r *ChannelRepository) RecordDelivery(ctx context.Context, id, status, errMsg string, sentAt time.Time) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE notification_channels SET last_status=$2, last_error=NULLIF($3,''), last_sent_at=$4, updated_at=now() WHERE id=$1`,
		id, status, errMsg, sentAt)
	return err
}
