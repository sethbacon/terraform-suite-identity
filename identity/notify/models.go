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
