// unguarded_egress_class_test.go is the CLASS TEST for "the module ships a safe
// outbound-HTTP guard and then makes requests that bypass it" (issues #137,
// #144, #153).
//
// The defect was never that identity/httpsafe was missing or wrong. It was that
// using it was OPTIONAL, including inside the module that owns it. The OIDC
// relying party — the surface that fetches the signing keys deciding which ID
// tokens are valid, and that carries the client_secret to an endpoint the
// ISSUER names — built a bare &http.Client{Timeout: ...} with Go's default
// cross-host redirect policy, while notify/notifier.go two directories away
// used httpsafe correctly and suite/discovery.go had independently solved a
// narrower version of the same problem a third way. Three call sites, three
// postures, one package that already had the answer.
//
// A guard that each new call site may or may not adopt is not a control; it is
// a convention, and conventions are audited by whoever happens to review the
// diff. So the enforcement is structural: THERE IS EXACTLY ONE PLACE IN THIS
// MODULE THAT CONSTRUCTS AN OUTBOUND HTTP TRANSPORT, and it is
// identity/httpsafe. Every other package must obtain its client from
// httpsafe.NewClient / NewClientWithTLS, which means every other package gets
// resolve-and-pin dialing, per-hop redirect re-validation and the proxy refusal
// whether or not its author was thinking about SSRF that day.
//
// The four checks below are the four ways a Go file can acquire an
// unguarded outbound client:
//
//  1. &http.Client{...} — a client with the default transport.
//  2. &http.Transport{...} — a transport with the default dialer.
//  3. http.DefaultClient / http.DefaultTransport — the process-wide ones.
//  4. http.Get / Post / Head / PostForm — package-level helpers that are
//     http.DefaultClient with a shorter name, which is exactly why they get
//     reached for.
//
// SCOPE. This guards HTTP. identity/mailer dials SMTP through net.Dialer and
// tls.Dialer, which httpsafe cannot wrap (it builds an *http.Client, not a
// generic dialer) and which is a different trust shape: the relay is
// operator-configured, named once in config, and never influenced by a remote
// party's response. That is a deliberate exclusion, recorded here rather than
// left for a reader to wonder about.
package identity

import (
	"go/ast"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// egressOwner is the ONLY package permitted to construct an outbound HTTP
// transport. Everything else obtains a client from it.
const egressOwner = "httpsafe/httpsafe.go"

// bannedPackageLevelCalls are net/http helpers that use http.DefaultClient.
var bannedPackageLevelCalls = map[string]bool{
	"Get": true, "Post": true, "Head": true, "PostForm": true,
}

// bannedSelectors are the process-wide client and transport.
var bannedSelectors = map[string]bool{
	"DefaultClient": true, "DefaultTransport": true,
}

// bannedCompositeTypes are the two types whose zero-ish literal is an unguarded
// egress path.
var bannedCompositeTypes = map[string]bool{
	"Client": true, "Transport": true,
}

// httpImportName returns the local name net/http is imported under in f, and
// whether it is imported at all. Almost always "http", but an aliased import
// must not slip past the checks below.
func httpImportName(f *ast.File) (string, bool) {
	for _, imp := range f.Imports {
		if imp.Path == nil || imp.Path.Value != `"net/http"` {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				// A blank import cannot be referenced; a dot import would make
				// these checks unsound, so refuse it outright.
				return imp.Name.Name, imp.Name.Name != "_"
			}
			return imp.Name.Name, true
		}
		return "http", true
	}
	return "", false
}

// isHTTPSelector reports whether e is `<httpName>.<sel>`.
func isHTTPSelector(e ast.Expr, httpName string) (string, bool) {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok || ident.Name != httpName {
		return "", false
	}
	return sel.Sel.Name, true
}

// TestNoUnguardedOutboundClientIsConstructedOutsideHTTPSafe is the guard. It
// fails on a NEW bypass anywhere in the module, which is the point: the next
// author to need an outbound request cannot reintroduce this class without the
// build telling them, in this file, why.
func TestNoUnguardedOutboundClientIsConstructedOutsideHTTPSafe(t *testing.T) {
	fset, files := moduleFiles(t)

	ownerSeen := false
	var findings []string
	report := func(pos token.Pos, format string) {
		findings = append(findings, fset.Position(pos).String()+": "+format)
	}

	for path, f := range files {
		if strings.HasSuffix(path, egressOwner) {
			ownerSeen = true
			continue // the one place allowed to build a transport
		}
		httpName, imported := httpImportName(f)
		if !imported {
			continue
		}
		if httpName == "." {
			report(f.Pos(), "net/http is dot-imported, which makes the unguarded-egress checks unsound; import it normally")
			continue
		}

		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CompositeLit:
				if name, ok := isHTTPSelector(node.Type, httpName); ok && bannedCompositeTypes[name] {
					report(node.Pos(), "constructs "+httpName+"."+name+"{...} directly. "+
						"That is an outbound path with the DEFAULT dialer and redirect policy: no "+
						"resolve-and-pin, no per-hop re-validation, cross-host redirects followed. "+
						"Obtain the client from httpsafe.NewClient (or NewClientWithTLS when the "+
						"caller supplies TLS material) instead")
				}
			case *ast.SelectorExpr:
				if name, ok := isHTTPSelector(node, httpName); ok && bannedSelectors[name] {
					report(node.Pos(), "references "+httpName+"."+name+", the process-wide unguarded "+
						"client/transport. Obtain the client from httpsafe.NewClient instead")
				}
			case *ast.CallExpr:
				if name, ok := isHTTPSelector(node.Fun, httpName); ok && bannedPackageLevelCalls[name] {
					report(node.Pos(), "calls "+httpName+"."+name+", which is http.DefaultClient with a "+
						"shorter name. Build a request and send it with a client from httpsafe.NewClient instead")
				}
			}
			return true
		})
	}

	// Non-vacuity, in both directions. If the walk stopped finding the owner —
	// a rename, a move, a refactor that split the transport out — every
	// assertion above would pass because nothing was being checked.
	if !ownerSeen {
		t.Fatalf("did not find %s among the parsed files. The egress owner moved or was renamed; "+
			"update egressOwner deliberately rather than letting this check pass vacuously.", egressOwner)
	}

	sort.Strings(findings)
	for _, f := range findings {
		t.Errorf("unguarded egress: %s", f)
	}
}

// TestHTTPSafeStillOwnsTheTransport is the other half of the non-vacuity pair:
// it asserts the owner actually contains what the exemption above exists for.
// Without it, deleting httpsafe's transport construction (and leaving every
// other package obtaining a client from a now-hollow helper) would be invisible.
func TestHTTPSafeStillOwnsTheTransport(t *testing.T) {
	_, files := moduleFiles(t)

	var owner *ast.File
	for path, f := range files {
		if strings.HasSuffix(path, egressOwner) {
			owner = f
			break
		}
	}
	if owner == nil {
		t.Fatalf("%s is not among the parsed files", egressOwner)
	}

	httpName, imported := httpImportName(owner)
	if !imported {
		t.Fatalf("%s does not import net/http; it cannot be constructing the transport", egressOwner)
	}

	foundTransport := false
	ast.Inspect(owner, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if name, ok := isHTTPSelector(lit.Type, httpName); ok && name == "Transport" {
			foundTransport = true
		}
		return true
	})
	if !foundTransport {
		t.Errorf("%s no longer constructs an %s.Transport. Either the guarded client moved "+
			"(update egressOwner) or the module has no guarded transport at all, in which case "+
			"the check above is exempting a file that guards nothing.", egressOwner, httpName)
	}
}

// TestGuardedTransportInstallsTheGuardsDialer pins WHAT the exempted
// construction has to do. Owning the only transport in the module is worth
// nothing if that transport dials however Go likes; this asserts the two fields
// that make it a guard rather than a plain client, at the level the AST can
// see.
func TestGuardedTransportInstallsTheGuardsDialer(t *testing.T) {
	_, files := moduleFiles(t)

	var owner *ast.File
	for path, f := range files {
		if strings.HasSuffix(path, egressOwner) {
			owner = f
			break
		}
	}
	if owner == nil {
		t.Fatalf("%s is not among the parsed files", egressOwner)
	}
	httpName, _ := httpImportName(owner)

	var dialContextSet, checkRedirectSet bool
	ast.Inspect(owner, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		name, ok := isHTTPSelector(lit.Type, httpName)
		if !ok {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch {
			case name == "Transport" && key.Name == "DialContext":
				dialContextSet = true
			case name == "Client" && key.Name == "CheckRedirect":
				checkRedirectSet = true
			}
		}
		return true
	})

	if !dialContextSet {
		t.Error("the guarded transport sets no DialContext: without it the resolve-and-pin check " +
			"never runs and every other package's 'guarded' client is guarded by nothing")
	}
	if !checkRedirectSet {
		t.Error("the guarded client sets no CheckRedirect: redirect hops would be followed under " +
			"Go's default policy, so a permitted first hop could hand off to a denied second one")
	}
}
