// insecure_zero_class_test.go is the CLASS TEST for "a zero value or default
// selects the insecure behaviour" (issues #145, #136).
//
// The class is not "a missing check". It is a defect of SHAPE: the type
// compiles, reviews and runs exactly as intended, and the only thing wrong with
// it is which way it points when a caller says nothing. Nothing fails, nothing
// logs, and the reviewer who would have to notice is reading a struct literal
// that is correct in every field it mentions.
//
// # Why a class guard rather than two fixes
//
// mailer.Config carried `UseTLS bool` for its whole life. It was deliberate,
// carefully reasoned and thoroughly documented — the doc comment explained
// precisely what false meant and why the plaintext path never upgrades
// opportunistically. It still shipped the wrong default, because a field-level
// doc comment is read by whoever was already going to read it, and the person
// writing `mailer.Config{Host: h, Port: p, From: f}` is by definition not that
// person. This package's OWN tests wrote that literal nine times.
//
// So the guard below is not about TLS. It is about POLARITY: a boolean whose
// TRUE value is the safe one has an unsafe zero value by construction, no
// matter how carefully it is documented, and the fix is always to invert the
// name (AllowInsecureIssuer, not RequireSecureIssuer) or to replace the bool
// with a type whose zero value names a safe choice (mailer.TLSMode).
//
// # What this file does and does not cover
//
// It covers the BOOLEAN form of the class, mechanically and bidirectionally:
// every exported boolean field in the module must be classified, an
// unclassified one fails, and a classification for a field that no longer
// exists fails too, so the inventory cannot rot into a list of things that used
// to be true.
//
// It does NOT try to infer, from names, whether a numeric zero means
// "unbounded". That judgement does not survive automation, so those members are
// pinned where their meaning lives instead:
//
//   - auth.MaxAPIKeyPrefixLength vs DisplayPrefixLength — a constant whose
//     value silently determined how much entropy reached the authentication
//     lookup — is enforced by a COMPILE-TIME assertion in identity/auth/apikey.go
//     and explained by TestMaxAPIKeyPrefixLength_LeavesRoomInTheLookupWindow.
//   - store.maxPrefixCandidates, which bounds that lookup's fan-out, is pinned
//     bidirectionally by TestGetAPIKeysByPrefix_FanOutBoundary.
//   - The defaulted knobs (oauthstate.NewMemoryStore's cleanupInterval and
//     maxEntries, crypto.DeriveTokenCipher's iterations, crypto.GenerateSalt's
//     length, notify.ExpiryConfig's WarningDays and CheckIntervalHours) all
//     already replace a non-positive argument with a safe default at the point
//     of use, and their own packages' tests cover that.
package identity

import (
	"go/ast"
	"sort"
	"strings"
	"testing"
)

// zeroMeaning classifies what a boolean field's ZERO VALUE (false) selects.
type zeroMeaning int

const (
	// zeroSafe: false is the safe/restrictive answer, so a caller who says
	// nothing is protected. Security booleans MUST be shaped this way, which
	// means they must be named for what setting them OPTS OUT of.
	zeroSafe zeroMeaning = iota

	// zeroInert: the field is not a security decision at all. False means the
	// feature is off, the record is inactive, or the flag is descriptive —
	// nothing is weakened by leaving it unset.
	zeroInert
)

// boolFields is the classified inventory of every exported boolean field in the
// module's exported structs.
//
// Adding a boolean to an exported struct requires adding it here, which is the
// point: the decision this file exists to force is "which way does it point
// when nobody sets it?", and that decision is easiest to get right while the
// field is being written and hardest to revisit afterwards.
//
// There is deliberately no zeroUnsafe classification. A boolean whose false is
// the dangerous answer has no correct entry in this table — it has a rename.
var boolFields = map[string]struct {
	meaning zeroMeaning
	why     string
}{
	"tenantscope.Scope.PlatformAdmin": {zeroSafe,
		"false means the scope reaches only the organizations it names. Every failure path in " +
			"Resolve returns the zero Scope, so a resolver that could not answer selects nothing."},
	"tenantscope.Resolver.AdminsApplyToAPIKeys": {zeroSafe,
		"false keeps a minted credential from inheriting its owner's platform authority. The name " +
			"is the opt-IN, so the default is the narrow reading and widening it is a word a " +
			"reviewer sees in the diff."},
	"tenantscope.Resolver.KeyBindsOrganization": {zeroSafe,
		"false ignores the organization named on an API key and resolves the owner's memberships " +
			"instead. Enabling it TRUSTS that column, which is only correct where it is written " +
			"from the acting organization rather than defaulted; terraform-state-manager defaults " +
			"it, so off is the answer that does not place every key in one organization."},

	"oidc.Config.AllowInsecureIssuer": {zeroSafe,
		"false requires an HTTPS issuer. The name is the opt-OUT, so the default is the strict " +
			"one and relaxing it is a word a reviewer sees in the diff. This is the shape " +
			"mailer.Config should have had from the start."},

	"store.TemplateReconcileResult.Done": {zeroSafe,
		"false is what a consumer must read as 'not confirmed complete, do not proceed to " +
			"UpdateRoleTemplate/DeleteRoleTemplate yet'. Every early return in ReconcileRoleTemplate " +
			"— ctx cancelled, MaxBatches reached, and the unpopulated zero value alike — reports " +
			"false; only a batch that planned a page and found it short of BatchSize sets it true. " +
			"A caller that mishandles or ignores the field is left holding the conservative answer, " +
			"the same direction issue #282 asks every guard in this file to fail toward."},

	"store.TemplateWritten.Mutated": {zeroSafe,
		"false means the template statement did not land — a refusal before the sweep, an " +
			"unfinished reconciliation, or a failed write — so a caller that reads nothing and " +
			"assumes the zero value concludes the edit did NOT take effect. That is the " +
			"conservative reading in both directions: an operator who believes a narrowing " +
			"landed when it did not goes and looks, whereas one who believes it landed when it " +
			"did not would stop looking. Every path that sets it true has already run the " +
			"credential sweep to completion."},

	"notify.NotificationChannel.Enabled": {zeroInert,
		"false means the channel does not deliver. A channel nobody enabled sending nothing is " +
			"the conservative outcome."},
	"notify.NotificationChannel.HasTarget": {zeroInert,
		"a read-only descriptor telling an API client whether an encrypted target is stored; it " +
			"gates nothing."},

	"notify.ExpiryConfig.Enabled": {zeroInert,
		"false leaves the expiry-notification job idle. Not running a background emailer weakens " +
			"nothing."},
	"notify.ExpiryConfig.APIKeyExpiring": {zeroInert,
		"false suppresses the expiry email. Same reasoning as Enabled."},

	"suite.IdentityInfo.SharedStore": {zeroInert,
		"a manifest claim about whether two apps share one identity database. False is the " +
			"conservative claim (assume they do not) and NegotiateCompat does not read it."},

	"models.OIDCConfig.IsActive": {zeroInert,
		"false means the IdP row is not in use. An inactive identity provider is the safe " +
			"direction for a record that arrives unset."},

	"models.RoleTemplate.IsSystem": {zeroInert,
		"false marks a template as operator-defined rather than built-in. It confers no " +
			"privilege; the scopes on the template do that."},
}

// exportedBoolFields walks the module and returns every exported boolean field
// of an exported struct type, keyed "pkg.Type.Field".
func exportedBoolFields(t *testing.T) map[string]string {
	t.Helper()
	_, files := moduleFiles(t)

	found := map[string]string{}
	for path, f := range files {
		pkg := f.Name.Name
		ast.Inspect(f, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok || !ts.Name.IsExported() {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, field := range st.Fields.List {
				ident, ok := field.Type.(*ast.Ident)
				if !ok || ident.Name != "bool" {
					continue
				}
				for _, name := range field.Names {
					if !name.IsExported() {
						continue
					}
					found[pkg+"."+ts.Name.Name+"."+name.Name] = path
				}
			}
			return true
		})
	}
	return found
}

// TestInsecureZeroClass_EveryExportedBoolIsClassified is the forward direction:
// a new boolean on an exported struct fails until someone states which way its
// zero value points.
func TestInsecureZeroClass_EveryExportedBoolIsClassified(t *testing.T) {
	found := exportedBoolFields(t)

	var unclassified []string
	for name, path := range found {
		if _, ok := boolFields[name]; !ok {
			unclassified = append(unclassified, name+" ("+path+")")
		}
	}
	sort.Strings(unclassified)

	if len(unclassified) > 0 {
		t.Fatalf("exported boolean field(s) with no entry in boolFields:\n  %s\n\n"+
			"Decide what FALSE means for each, then add it. If false is the LESS SAFE answer, "+
			"the field is a member of the defect class this file guards and the fix is to rename "+
			"it for what setting it opts OUT of (see oidc.Config.AllowInsecureIssuer) or to give "+
			"it a type whose zero value names a safe choice (see mailer.TLSMode) — not to add an "+
			"entry saying so.",
			strings.Join(unclassified, "\n  "))
	}
}

// TestInsecureZeroClass_NoStaleClassifications is the reverse direction, and it
// is what stops the inventory above from decaying into documentation.
//
// Without it, a field could be deleted or renamed and its entry would sit here
// asserting a fact about code that no longer exists, while the guard above went
// on passing.
func TestInsecureZeroClass_NoStaleClassifications(t *testing.T) {
	found := exportedBoolFields(t)

	var stale []string
	for name := range boolFields {
		if _, ok := found[name]; !ok {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)

	if len(stale) > 0 {
		t.Fatalf("boolFields classifies field(s) that no longer exist:\n  %s\n\n"+
			"Remove the entries, or fix the names if the fields were renamed.",
			strings.Join(stale, "\n  "))
	}
}

// TestInsecureZeroClass_NoSecurityBoolIsOptIn is the substantive guard: it
// rejects the NAMING SHAPE that produces the defect, independently of whether
// anyone remembered to classify the field honestly.
//
// A boolean named for the protection it turns ON is unsafe-by-omission by
// construction — the zero value is "protection off" — so `UseTLS`,
// `VerifySignature` and `RequireHTTPS` are all the same bug regardless of how
// their doc comments read. The safe shape names the RELAXATION instead:
// AllowInsecureIssuer, DisableX, SkipY. The two vocabularies are what this
// checks.
//
// The inert fields above are exempt by classification, not by name: `Enabled`
// on a notification channel is a feature switch, not a control.
func TestInsecureZeroClass_NoSecurityBoolIsOptIn(t *testing.T) {
	// Prefixes that mean "turning this ON adds protection", i.e. the zero
	// value removes it.
	optInSecurity := []string{
		"Use", "Require", "Verify", "Validate", "Enforce", "Check", "Strict", "Secure", "Protect",
	}

	found := exportedBoolFields(t)

	var offenders []string
	for name := range found {
		cls, ok := boolFields[name]
		if !ok || cls.meaning == zeroInert {
			// Unclassified fields are the other test's business; inert ones
			// are not security decisions.
			continue
		}
		short := name[strings.LastIndex(name, ".")+1:]
		for _, p := range optInSecurity {
			if strings.HasPrefix(short, p) {
				offenders = append(offenders, name+" (found "+found[name]+")")
				break
			}
		}
	}
	sort.Strings(offenders)

	if len(offenders) > 0 {
		t.Fatalf("security boolean(s) named for the protection they ENABLE, so the zero value "+
			"disables it:\n  %s\n\nName the relaxation instead (AllowX, DisableX, SkipX) so an "+
			"unset field is the strict one.", strings.Join(offenders, "\n  "))
	}
}

// TestInsecureZeroClass_MailerHasNoBooleanTLSSwitch pins the specific
// regression, in the specific place, in a form that survives a rename.
//
// The class guard above would not catch a reintroduced `mailer.Config.UseTLS`
// on its own: someone adding it would hit the "unclassified" failure and could
// make it green by classifying it inert. This says the transport-security
// choice on mailer.Config is not allowed to be a boolean AT ALL, which is the
// actual conclusion of issue #145 — the field has three legitimate states over
// time (required, disabled, and "the caller has not said"), and a bool can only
// represent two of them.
func TestInsecureZeroClass_MailerHasNoBooleanTLSSwitch(t *testing.T) {
	for name := range exportedBoolFields(t) {
		if strings.HasPrefix(name, "mailer.Config.") {
			t.Fatalf("mailer.Config has a boolean field %q. Transport security on this type is "+
				"expressed as a TLSMode whose zero value is TLSRequired; a boolean cannot "+
				"distinguish 'plaintext, deliberately' from 'nobody said', and defaulting that "+
				"ambiguity to plaintext is issue #145.", name)
		}
	}
}
