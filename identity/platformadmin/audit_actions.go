// audit_actions.go holds the audit vocabulary for carrier mutations.
//
// Constants rather than literals because the strings are load-bearing across
// package boundaries the moment the carrier acquires more than one caller: a
// first-boot bootstrap grant, the management API, and whatever lifecycle
// cleanup retires a destroyed principal's grant are typically three different
// packages writing what has to be the same action string. An application that
// pins these in a database constraint — as registry does, with a deferred
// constraint trigger requiring an intent naming THIS subject with THIS action —
// turns a second spelling into a failed COMMIT rather than a wrong audit entry,
// and that is only worth doing if there is one definition to pin.
package platformadmin

const (
	// AuditActionGranted names the grant of platform-admin authority.
	AuditActionGranted = "platform_admin.granted"

	// AuditActionRevoked names its removal.
	AuditActionRevoked = "platform_admin.revoked"

	// AuditResourceType is the resource_type both actions carry, so an
	// auditor can select the whole history of the privilege with one
	// predicate.
	AuditResourceType = "platform_admin"
)
