//go:build e2e

package scenarios

import (
	"net/http"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// Topology: enterprise-xaa (docs/topologies/enterprise-xaa.md).
//
// The corporate IdP (the harness MockIdP) signs an ID-JAG naming the agent;
// the agent presents it at /oauth/token with the jwt-bearer grant. The AS
// verifies it against a trusted_idps row, resolves the subject (auto_map →
// "<iss>:<sub>", or a subject_mappings row → a local user), applies the XAA
// policy, and mints an ordinary JWT with act.sub = the IdP. Audit rows are
// jwt_bearer.issued / jwt_bearer.denied.
//
// The agent is a confidential admin-registered client with the jwt-bearer
// grant and a scope ceiling; the trusted IdP is registered through the
// harness (the admin endpoint insists on https, which an httptest IdP cannot
// offer); policies and subject mappings go through the admin HTTP API.

type xaaFixture struct {
	h              *e2e.TestHarness
	rs             *e2e.MCPResourceServer
	idp            *e2e.MockIdP
	idpID          string
	agent, secret  string
	otherURI       string
	rsID, rsSecret string
}

func newXAAFixture(t *testing.T, subjectMode string) *xaaFixture {
	t.Helper()
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true, EnableXAA: true, XAASubjectMode: subjectMode,
	}, []string{"tools/echo", "tools/db_query"})
	f := &xaaFixture{h: h, rs: servers[0], idp: e2e.NewMockIdP(t), otherURI: "https://mcp-b.xaa.test"}
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug: "mcp-b", URI: f.otherURI, BackendKind: "mint", DisplayName: "mcp-b",
		Scopes: []e2e.AdminScope{{Name: "tools/echo"}},
	})
	f.idpID = h.RegisterTrustedIDPSimple("Corp IdP", f.idp.Issuer, "")
	f.agent, f.secret = topoCreateClient(t, h, map[string]any{
		"client_name": "enterprise-agent", "grant_types": []string{topoGrantJWT},
		"token_endpoint_auth_method": "client_secret_basic", "scope": "tools/echo tools/db_query",
	})
	f.rsID, f.rsSecret = topoRSCreds(t, h, "mcp-0")
	return f
}

func (f *xaaFixture) assertion(t *testing.T, clientID, subject, scope, resource string) string {
	t.Helper()
	return f.idp.SignIDJAGCustom(t, e2e.IDJAGOptions{
		Audience: f.h.Issuer, ClientID: clientID, Subject: subject, Scope: scope, Resource: resource,
	})
}

func (f *xaaFixture) grant(t *testing.T, auth topoAuth, clientID, secret, assertion, scope, resource string) topoResp {
	t.Helper()
	form := map[string][]string{"grant_type": {topoGrantJWT}, "assertion": {assertion}}
	if scope != "" {
		form["scope"] = []string{scope}
	}
	if resource != "" {
		form["resource"] = []string{resource}
	}
	return topoToken(t, f.h, form, auth, clientID, secret)
}

func TestTopologyEnterpriseXAA_Adversarial(t *testing.T) {
	t.Parallel()
	t.Run("LegitimateFlow_DocumentedShape_BothAuthMethods", func(t *testing.T) {
		t.Parallel()
		f := newXAAFixture(t, "")
		f.h.AdminCreateXAAPolicy(e2e.XAAPolicySpec{Name: "allow", IDPID: f.idpID})
		for _, auth := range topoBothAuth {
			r := f.grant(t, auth, f.agent, f.secret, f.assertion(t, f.agent, "alice@corp", "tools/echo", f.rs.URI), "tools/echo", f.rs.URI)
			if !r.OK() {
				t.Fatalf("%s: jwt-bearer: %d %s", auth, r.Status, r.Raw)
			}
			c := parseJWTClaims(t, r.AccessToken())
			if aud := topoAud(c); len(aud) != 1 || aud[0] != f.rs.URI {
				t.Errorf("%s: aud = %v", auth, aud)
			}
			if stringClaim(c, "sub") != f.idp.Issuer+":alice@corp" || stringClaim(c, "client_id") != f.agent || stringClaim(c, "scope") != "tools/echo" {
				t.Errorf("%s: sub/client_id/scope = %q/%q/%q", auth, stringClaim(c, "sub"), stringClaim(c, "client_id"), stringClaim(c, "scope"))
			}
			if topoActSub(c, 1) != f.idp.Issuer {
				t.Errorf("%s: act.sub = %q, want the IdP issuer (provenance)", auth, topoActSub(c, 1))
			}
			mc := e2e.NewMCPClient(t, f.h, f.rs, f.agent, topoRedirect)
			if st, _ := mc.CallTool("/tools/echo", r.AccessToken(), `"xaa"`); st != http.StatusOK {
				t.Errorf("%s: RS call: %d", auth, st)
			}
		}
		topoExpectAudit(t, f.h, "jwt_bearer.issued", "idp=… scopes=tools/echo", func(r topoAuditRow) bool {
			return r.ClientID == f.agent && topoDetailHas(r.Detail, "jti=", "idp=", "scopes=tools/echo")
		})
	})

	t.Run("OmittedParameters_DocumentedDefaults", func(t *testing.T) {
		t.Parallel()
		f := newXAAFixture(t, "")
		f.h.AdminCreateXAAPolicy(e2e.XAAPolicySpec{Name: "allow", IDPID: f.idpID})
		// scope omitted in the request: the assertion's scope bounds it.
		r := f.grant(t, topoAuthBasic, f.agent, f.secret, f.assertion(t, f.agent, "alice@corp", "tools/echo", f.rs.URI), "", f.rs.URI)
		if !r.OK() {
			t.Fatalf("scope omitted: %s", r.Raw)
		}
		topoAssertScopeWithin(t, "request scope omitted", r.Scope(), true, "tools/echo")
		// resource omitted in the request: the assertion's resource applies.
		r = f.grant(t, topoAuthBasic, f.agent, f.secret, f.assertion(t, f.agent, "alice@corp", "tools/echo", f.rs.URI), "tools/echo", "")
		if !r.OK() {
			t.Fatalf("request resource omitted: %s", r.Raw)
		}
		if aud := topoAud(parseJWTClaims(t, r.AccessToken())); len(aud) != 1 || aud[0] != f.rs.URI {
			t.Errorf("resource from the assertion: aud = %v, want [%s]", aud, f.rs.URI)
		}
		// resource omitted everywhere: aud = issuer, which no RS accepts.
		r = f.grant(t, topoAuthBasic, f.agent, f.secret, f.assertion(t, f.agent, "alice@corp", "tools/echo", ""), "tools/echo", "")
		if r.OK() {
			mc := e2e.NewMCPClient(t, f.h, f.rs, f.agent, topoRedirect)
			if st, _ := mc.CallTool("/tools/echo", r.AccessToken(), `"x"`); st != http.StatusUnauthorized {
				t.Errorf("resource-less XAA token accepted by the RS: %d", st)
			}
		}
	})

	t.Run("UnderPrivileged_ClientCeilingAndPolicyBoundScope", func(t *testing.T) {
		t.Parallel()
		f := newXAAFixture(t, "")
		f.h.AdminCreateXAAPolicy(e2e.XAAPolicySpec{Name: "echo-only", IDPID: f.idpID, Scopes: []string{"tools/echo"}})
		narrow, narrowSecret := topoCreateClient(t, f.h, map[string]any{
			"client_name": "narrow-agent", "grant_types": []string{topoGrantJWT},
			"token_endpoint_auth_method": "client_secret_basic", "scope": "tools/echo",
		})
		r := f.grant(t, topoAuthBasic, narrow, narrowSecret, f.assertion(t, narrow, "alice@corp", "tools/echo tools/db_query", f.rs.URI), "tools/db_query", f.rs.URI)
		if r.OK() || r.Err() != "invalid_scope" {
			t.Errorf("beyond client ceiling: status %d error %q, want invalid_scope", r.Status, r.Err())
		}
		r = f.grant(t, topoAuthBasic, f.agent, f.secret, f.assertion(t, f.agent, "alice@corp", "tools/echo tools/db_query", f.rs.URI), "tools/db_query", f.rs.URI)
		if r.OK() || r.Err() != "access_denied" || r.Status != http.StatusForbidden {
			t.Errorf("beyond policy scope: status %d error %q, want 403 access_denied", r.Status, r.Err())
		}
		// Omitted request scope must not widen past the policy either.
		r = f.grant(t, topoAuthBasic, f.agent, f.secret, f.assertion(t, f.agent, "alice@corp", "", f.rs.URI), "", f.rs.URI)
		if r.OK() {
			topoAssertScopeWithin(t, "policy-bounded default", r.Scope(), true, "tools/echo")
		}
		topoExpectAudit(t, f.h, "jwt_bearer.denied", "reason=policy_denied", func(row topoAuditRow) bool {
			return row.ClientID == f.agent && strings.Contains(row.Detail, "reason=policy_denied")
		})
	})

	t.Run("PolicyResourceRestriction_CannotRetarget", func(t *testing.T) {
		t.Parallel()
		f := newXAAFixture(t, "")
		f.h.AdminCreateXAAPolicy(e2e.XAAPolicySpec{Name: "mcp-0 only", IDPID: f.idpID, Resources: []string{f.rs.URI}})
		r := f.grant(t, topoAuthBasic, f.agent, f.secret, f.assertion(t, f.agent, "alice@corp", "tools/echo", ""), "tools/echo", f.otherURI)
		if r.OK() || r.Err() != "access_denied" {
			t.Errorf("resource outside policy: status %d error %q, want access_denied", r.Status, r.Err())
		}
		// Assertion names one resource, the request another.
		r = f.grant(t, topoAuthBasic, f.agent, f.secret, f.assertion(t, f.agent, "alice@corp", "tools/echo", f.rs.URI), "tools/echo", f.otherURI)
		if r.OK() {
			t.Error("request resource overrode the assertion's resource")
		}
	})

	t.Run("ForeignClient_Refused", func(t *testing.T) {
		t.Parallel()
		f := newXAAFixture(t, "")
		f.h.AdminCreateXAAPolicy(e2e.XAAPolicySpec{Name: "agent only", IDPID: f.idpID, ClientIDs: []string{f.agent}})
		other, otherSecret := topoCreateClient(t, f.h, map[string]any{
			"client_name": "other-agent", "grant_types": []string{topoGrantJWT},
			"token_endpoint_auth_method": "client_secret_basic", "scope": "tools/echo",
		})
		for _, auth := range topoBothAuth {
			// An ID-JAG issued to the agent, presented by someone else.
			if r := f.grant(t, auth, other, otherSecret, f.assertion(t, f.agent, "alice@corp", "tools/echo", f.rs.URI), "tools/echo", f.rs.URI); r.OK() || r.Err() != "invalid_client" {
				t.Errorf("%s: stolen assertion: status %d error %q, want invalid_client", auth, r.Status, r.Err())
			}
			// Its own ID-JAG, but the policy names only the agent.
			if r := f.grant(t, auth, other, otherSecret, f.assertion(t, other, "alice@corp", "tools/echo", f.rs.URI), "tools/echo", f.rs.URI); r.OK() || r.Err() != "access_denied" {
				t.Errorf("%s: client outside policy: status %d error %q, want access_denied", auth, r.Status, r.Err())
			}
		}
		noGrant, noGrantSecret := topoCreateClient(t, f.h, map[string]any{
			"client_name": "code-only", "grant_types": []string{"authorization_code"}, "response_types": []string{"code"},
			"token_endpoint_auth_method": "client_secret_basic", "scope": "tools/echo",
		})
		if r := f.grant(t, topoAuthBasic, noGrant, noGrantSecret, f.assertion(t, noGrant, "alice@corp", "tools/echo", f.rs.URI), "tools/echo", f.rs.URI); r.Err() != "unauthorized_client" {
			t.Errorf("client without jwt-bearer: error %q, want unauthorized_client", r.Err())
		}
		topoExpectAudit(t, f.h, "jwt_bearer.denied", "reason=client_mismatch", func(row topoAuditRow) bool {
			return row.ClientID == other && strings.Contains(row.Detail, "reason=client_mismatch")
		})
	})

	// A client with no registered scope is fail-closed on the machine grants
	// ("deny-all on the machine grants today", internal/services/dcr.go), and
	// open DCR hands out exactly such clients to anyone. An assertion that
	// names no scope must not let the policy's maximum fill the gap.
	t.Run("EmptyCeilingClient_CannotBorrowPolicyScopes", func(t *testing.T) {
		t.Parallel()
		f := newXAAFixture(t, "")
		f.h.AdminCreateXAAPolicy(e2e.XAAPolicySpec{Name: "echo", IDPID: f.idpID, Scopes: []string{"tools/echo"}})
		anon, anonSecret := topoDCR(t, f.h, map[string]any{
			"client_name": "self-registered", "grant_types": []string{topoGrantJWT},
			"token_endpoint_auth_method": "client_secret_basic",
		})
		r := f.grant(t, topoAuthBasic, anon, anonSecret, f.assertion(t, anon, "alice@corp", "", f.rs.URI), "", f.rs.URI)
		if r.OK() && strings.TrimSpace(r.Scope()) != "" {
			t.Errorf("%s: a DCR-registered client with an empty scope ceiling obtained scope %q for %s by leaving scope out of both assertion and request (the policy's maximum replaced the empty ceiling)",
				topoFindingPrefix, r.Scope(), f.rs.URI)
		}
	})

	t.Run("AssertionIntegrity_UntrustedDisabledReplayedMisaudienced", func(t *testing.T) {
		t.Parallel()
		f := newXAAFixture(t, "")
		f.h.AdminCreateXAAPolicy(e2e.XAAPolicySpec{Name: "allow", IDPID: f.idpID})
		rogueIdP := e2e.NewMockIdP(t)
		untrusted := rogueIdP.SignIDJAGCustom(t, e2e.IDJAGOptions{Audience: f.h.Issuer, ClientID: f.agent, Subject: "alice@corp", Scope: "tools/echo"})
		if r := f.grant(t, topoAuthBasic, f.agent, f.secret, untrusted, "tools/echo", f.rs.URI); r.OK() || r.Err() != "invalid_grant" {
			t.Errorf("untrusted issuer: status %d error %q, want invalid_grant", r.Status, r.Err())
		}
		// Forged: the trusted issuer's name, a key the trusted JWKS lacks.
		forged := rogueIdP.SignIDJAGCustom(t, e2e.IDJAGOptions{Issuer: f.idp.Issuer, Audience: f.h.Issuer, ClientID: f.agent, Subject: "ceo@corp", Scope: "tools/echo"})
		if r := f.grant(t, topoAuthBasic, f.agent, f.secret, forged, "tools/echo", f.rs.URI); r.OK() {
			t.Error("assertion signed by an untrusted key under the trusted issuer's name was accepted")
		}
		misaud := f.idp.SignIDJAGCustom(t, e2e.IDJAGOptions{Audience: "https://some-other-as.test", ClientID: f.agent, Subject: "alice@corp", Scope: "tools/echo"})
		if r := f.grant(t, topoAuthBasic, f.agent, f.secret, misaud, "tools/echo", f.rs.URI); r.OK() {
			t.Error("assertion audienced to another AS was accepted")
		}
		once := f.assertion(t, f.agent, "alice@corp", "tools/echo", f.rs.URI)
		if r := f.grant(t, topoAuthBasic, f.agent, f.secret, once, "tools/echo", f.rs.URI); !r.OK() {
			t.Fatalf("first use: %s", r.Raw)
		}
		if r := f.grant(t, topoAuthPost, f.agent, f.secret, once, "tools/echo", f.rs.URI); r.OK() || r.Err() != "invalid_grant" {
			t.Errorf("replayed assertion: status %d error %q, want invalid_grant", r.Status, r.Err())
		}
		f.h.AdminSetIDPEnabled(f.idpID, false)
		if r := f.grant(t, topoAuthBasic, f.agent, f.secret, f.assertion(t, f.agent, "alice@corp", "tools/echo", f.rs.URI), "tools/echo", f.rs.URI); r.OK() || r.Err() != "invalid_grant" {
			t.Errorf("disabled IdP: status %d error %q, want invalid_grant", r.Status, r.Err())
		}
		for _, reason := range []string{"untrusted_issuer", "replay", "idp_disabled"} {
			topoExpectAudit(t, f.h, "jwt_bearer.denied", "reason="+reason, func(row topoAuditRow) bool {
				return strings.Contains(row.Detail, "reason="+reason)
			})
		}
	})

	t.Run("StrictSubjectMode_UnmappedRefused", func(t *testing.T) {
		t.Parallel()
		f := newXAAFixture(t, "strict")
		f.h.AdminCreateXAAPolicy(e2e.XAAPolicySpec{Name: "allow", IDPID: f.idpID})
		r := f.grant(t, topoAuthBasic, f.agent, f.secret, f.assertion(t, f.agent, "stranger@corp", "tools/echo", f.rs.URI), "tools/echo", f.rs.URI)
		if r.OK() {
			t.Errorf("strict mode minted for an unmapped subject: sub=%q", stringClaim(parseJWTClaims(t, r.AccessToken()), "sub"))
		}
		topoExpectAudit(t, f.h, "jwt_bearer.denied", "reason=subject_mapping_failed", func(row topoAuditRow) bool {
			return strings.Contains(row.Detail, "reason=subject_mapping_failed")
		})
	})

	// A subject mapping resolves the IdP subject to a local user. Every other
	// grant stops for a disabled local user (code redemption, refresh,
	// introspection's subject_inactive); XAA is "per-user audit anchored on a
	// corporate-IdP-signed assertion" and must too.
	t.Run("MappedLocalUser_DisabledUserStopsXAA", func(t *testing.T) {
		t.Parallel()
		f := newXAAFixture(t, "")
		f.h.AdminCreateXAAPolicy(e2e.XAAPolicySpec{Name: "allow", IDPID: f.idpID})
		bob := f.h.CreateUser("bob@corp.example", topoPassword)
		f.h.AdminCreateSubjectMapping(f.idpID, "bob@corp", bob)
		r := f.grant(t, topoAuthBasic, f.agent, f.secret, f.assertion(t, f.agent, "bob@corp", "tools/echo", f.rs.URI), "tools/echo", f.rs.URI)
		if !r.OK() {
			t.Fatalf("mapped subject: %s", r.Raw)
		}
		if sub := stringClaim(parseJWTClaims(t, r.AccessToken()), "sub"); sub != bob {
			t.Fatalf("sub = %q, want the mapped local user %q", sub, bob)
		}
		f.h.DisableUser(bob)
		if f.h.IntrospectToken(r.AccessToken(), f.rsID, f.rsSecret).Active {
			t.Errorf("%s: XAA token whose sub is a now-disabled local user still introspects active (it is filed as a machine token, so the subject check is skipped)", topoFindingPrefix)
		}
		again := f.grant(t, topoAuthBasic, f.agent, f.secret, f.assertion(t, f.agent, "bob@corp", "tools/echo", f.rs.URI), "tools/echo", f.rs.URI)
		if again.OK() {
			t.Errorf("%s: jwt-bearer minted a fresh token for disabled local user %s through the subject mapping", topoFindingPrefix, bob)
		}
	})

	t.Run("RevocationReach_RevokeAndSuspend", func(t *testing.T) {
		t.Parallel()
		f := newXAAFixture(t, "")
		f.h.AdminCreateXAAPolicy(e2e.XAAPolicySpec{Name: "allow", IDPID: f.idpID})
		a := f.grant(t, topoAuthBasic, f.agent, f.secret, f.assertion(t, f.agent, "alice@corp", "tools/echo", f.rs.URI), "tools/echo", f.rs.URI)
		b := f.grant(t, topoAuthBasic, f.agent, f.secret, f.assertion(t, f.agent, "alice@corp", "tools/echo", f.rs.URI), "tools/echo", f.rs.URI)
		if !a.OK() || !b.OK() {
			t.Fatal("precondition")
		}
		if st := f.h.RevokeToken(a.AccessToken(), f.agent, f.secret); st != http.StatusOK {
			t.Errorf("revoke: %d", st)
		}
		if f.h.IntrospectToken(a.AccessToken(), f.rsID, f.rsSecret).Active {
			t.Error("revoked XAA token still active")
		}
		topoAdminPatch(t, f.h, "/admin/clients/"+f.agent+"/suspend")
		if f.h.IntrospectToken(b.AccessToken(), f.rsID, f.rsSecret).Active {
			t.Error("XAA token of a suspended client still active")
		}
		if r := f.grant(t, topoAuthBasic, f.agent, f.secret, f.assertion(t, f.agent, "alice@corp", "tools/echo", f.rs.URI), "tools/echo", f.rs.URI); r.OK() || r.Err() != "invalid_client" {
			t.Errorf("suspended client: status %d error %q, want invalid_client", r.Status, r.Err())
		}
	})
}
