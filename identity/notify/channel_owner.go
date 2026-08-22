package notify

import (
	"errors"
	"strings"
)

// ErrEmptyOwningOrganization is returned by Create when WithOwningOrganization
// was supplied with a blank id.
//
// It is an ERROR rather than a silent fallback to the column DEFAULT, because
// those two outcomes are indistinguishable at the call site and land the row in
// different tenants. A consumer that means "let the schema decide" says so by
// passing no option at all.
var ErrEmptyOwningOrganization = errors.New("notify: WithOwningOrganization was given an empty organization id")

// ChannelWriteOption customizes an INSERT. It is a separate type from
// ChannelQueryOption on purpose: a query option is a PREDICATE over rows that
// exist, a write option supplies a VALUE for a row that does not, and the two
// are not interchangeable even where both concern the same column.
type ChannelWriteOption func(*channelWrite)

type channelWrite struct {
	organizationID string
	haveOrg        bool
}

// WithOwningOrganization names the organization that will own the inserted row.
//
// WHY THIS EXISTS, given that Create's contract used to say the opposite.
//
// The old reasoning was that a partitioning consumer assigns the owner with a
// column DEFAULT in its own migration, keeping ownership a property of the
// schema. That holds for a BACKFILL and fails for a tenant: a DEFAULT is a
// static expression evaluated without reference to the caller, so under
// terraform-state-manager's tsm_default_organization_id() every organization's
// channel is inserted into the DEFAULT organization -- invisible to the tenant
// that created it, visible to whoever owns the default, and non-NULL, so the
// boot backfill that repairs NULLs never looks at it.
//
// The distinction the old comment was reaching for is still right: this package
// does not DECIDE the owner. It just stops preventing the consumer from deciding.
// Supply the option and the column is NAMED in the INSERT; omit it and the
// column is OMITTED, so the DEFAULT still applies for consumers that do not
// partition. Naming it with an empty value is the one thing that must not happen
// -- that writes NULL and takes the row out of every tenant's view -- so it is
// refused rather than defaulted.
func WithOwningOrganization(organizationID string) ChannelWriteOption {
	return func(w *channelWrite) {
		w.organizationID = strings.TrimSpace(organizationID)
		w.haveOrg = true
	}
}

// newChannelWrite folds the options and validates them.
func newChannelWrite(opts []ChannelWriteOption) (*channelWrite, error) {
	w := &channelWrite{}
	for _, opt := range opts {
		if opt != nil {
			opt(w)
		}
	}
	if w.haveOrg && w.organizationID == "" {
		return nil, ErrEmptyOwningOrganization
	}
	return w, nil
}

// columns returns the extra column names and their values for the INSERT,
// in matching order.
func (w *channelWrite) columns() (names []string, values []any) {
	if w.haveOrg {
		names = append(names, "organization_id")
		values = append(values, w.organizationID)
	}
	return names, values
}
