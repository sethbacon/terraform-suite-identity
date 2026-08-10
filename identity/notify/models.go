// Package notify delivers alert events to admin-configured notification
// channels (generic webhook, Slack/Teams incoming-webhook, or email via the
// shared SMTP relay) and periodically warns users about expiring API keys.
// It is shared by every Terraform suite app so a security fix (SSRF egress
// guard, webhook-secret redaction, key-rotation-capable encryption) only ever
// needs to be made — or verified — once.
//
// Each app defines its own event-type string constants locally (e.g.
// "module_published" for the registry, "drift_detected" for the state
// manager) and passes them in notify.Event.Type / channel.Events; this
// package is intentionally agnostic of what events exist.
package notify

import (
	"time"
)

// TargetContext returns the additional-authenticated-data context that binds a
// channel's encrypted target to that channel row (#153).
//
// Pass it to crypto.TokenCipher.SealWithContext when writing EncryptedTarget and
// to OpenWithContext / OpenWithContextOrLegacy when reading. Binding the
// ciphertext to the row id is what stops a target being lifted out of one
// channel and written into another by anyone with database write access — GCM
// authenticates the move otherwise, because nothing in the ciphertext says where
// it belongs.
//
// This function is exported, and is the ONLY definition, on purpose. The write
// happens in the host application and the read happens in this package, so the
// two halves live in different repositories; a host deriving its own equivalent
// string would work right up until one side's format changed, and then every
// channel target would fail to decrypt at delivery time. Hosts must call this
// rather than construct the value.
//
// Changing the returned format is a breaking change for stored data: every
// already-bound ciphertext stops opening. If it ever has to change, it needs the
// same treatment the original adoption gets — a transition read that accepts
// both, then a backfill.
func TargetContext(channelID string) []byte {
	return []byte("identity/notify:notification_channel:" + channelID + ":encrypted_target")
}

// NotificationChannel is a destination for alert events: an admin-configured
// webhook/Slack/Teams URL, or an ad-hoc email recipient list. The target is
// held encrypted (EncryptedTarget) and never serialized to API callers;
// HasTarget reports whether one is configured without exposing the secret.
type NotificationChannel struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Type            string     `json:"type"` // webhook | slack | teams | email
	EncryptedTarget string     `json:"-"`
	HasTarget       bool       `json:"has_target"`
	Events          []string   `json:"events"` // empty = all events
	Enabled         bool       `json:"enabled"`
	LastStatus      *string    `json:"last_status"`
	LastError       *string    `json:"last_error"`
	LastSentAt      *time.Time `json:"last_sent_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}
