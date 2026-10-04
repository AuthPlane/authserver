//go:build e2e

package scenarios

import (
	"net/http"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// Topology: m2m-client-credentials (docs/topologies/m2m-client-credentials.md).
//
// A backend registered through POST /admin/clients as the page prescribes
// (grant_types=[client_credentials], client_secret_basic, scope = the one it
// needs) mints tokens for a Mint Resource with no user in the loop. The page
// promises: sub == client_id, aud == resource URI, no refresh token, the
// requested scope bounded by the client's registered scopes, and a
// client_credentials.issued audit row. The guide adds: scope omitted → all
// registered scopes; resource omitted → aud = issuer.
//
// The adversaries are a client that authenticates badly, one that asks for
// more than it is registered for, one registered for a *different* resource,
// and an anonymous client registered through open DCR.

type m2mFixture struct {
	h                  *e2e.TestHarness
	rs                 *e2e.MCPResourceServer
	backend, secret    string
	metricsURI         string
	rsID, rsSecret     string
	internalScope      string
	internalScopeOther string
}

func newM2MFixture(t *testing.T) *m2mFixture {
	t.Helper()
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{EnableAdminAPI: true, EnableClientCredentials: true},
		[]string{"tools/echo", "tools/db_query"})
	f := &m2mFixture{h: h, rs: servers[0], internalScope: "tools/echo", internalScopeOther: "tools/db_query"}
	f.backend, f.secret = topoCreateClient(t, h, map[string]any{
		"client_name": "ingestor-cron", "grant_types": []string{"client_credentials"},
		"token_endpoint_auth_method": "client_secret_basic", "scope": "tools/echo",
	})
	// An unrelated Resource with its own catalog, the foreign client's home.
	f.metricsURI = "https://metrics.m2m.test"
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug: "internal-metrics", URI: f.metricsURI, BackendKind: "mint", DisplayName: "metrics",
		Scopes: []e2e.AdminScope{{Name: "emit"}},
	})
	f.rsID, f.rsSecret = topoRSCreds(t, h, "mcp-0")
	return f
}

func TestTopologyM2MClientCredentials_Adversarial(t *testing.T) {
	t.Parallel()
	t.Run("LegitimateFlow_BothAuthMethods_DocumentedShape", func(t *testing.T) {
		t.Parallel()
		f := newM2MFixture(t)
		for _, auth := range topoBothAuth {
			t.Run(auth.String(), func(t *testing.T) {
				r := topoToken(t, f.h, topoCCForm(f.rs.URI, "tools/echo"), auth, f.backend, f.secret)
				if !r.OK() {
					t.Fatalf("mint: %d %s", r.Status, r.Raw)
				}
				if r.Refresh() != "" {
					t.Error("client_credentials issued a refresh token")
				}
				c := parseJWTClaims(t, r.AccessToken())
				if aud := topoAud(c); len(aud) != 1 || aud[0] != f.rs.URI {
					t.Errorf("aud = %v, want [%s]", aud, f.rs.URI)
				}
				if stringClaim(c, "sub") != f.backend || stringClaim(c, "client_id") != f.backend {
					t.Errorf("sub/client_id = %q/%q, want both %q (RFC 9068 §2.2)", stringClaim(c, "sub"), stringClaim(c, "client_id"), f.backend)
				}
				if stringClaim(c, "scope") != "tools/echo" {
					t.Errorf("scope = %q, want tools/echo", stringClaim(c, "scope"))
				}
				if _, has := c["act"]; has {
					t.Error("machine token carries an act claim")
				}
				mc := e2e.NewMCPClient(t, f.h, f.rs, f.backend, topoRedirect)
				if st, _ := mc.CallTool("/tools/echo", r.AccessToken(), `"m2m"`); st != http.StatusOK {
					t.Errorf("RS call: status %d, want 200", st)
				}
			})
		}
		topoExpectAudit(t, f.h, "client_credentials.issued", "for the backend", func(r topoAuditRow) bool {
			return r.ActorID == f.backend && r.ClientID == f.backend && topoDetailHas(r.Detail, "jti=", "scopes=tools/echo")
		})
	})

	t.Run("OmittedParameters_DocumentedDefaults", func(t *testing.T) {
		t.Parallel()
		f := newM2MFixture(t)
		noScope := topoToken(t, f.h, topoCCForm(f.rs.URI, ""), topoAuthBasic, f.backend, f.secret)
		if !noScope.OK() {
			t.Fatalf("scope omitted: %d %s", noScope.Status, noScope.Raw)
		}
		// Documented default: every registered scope, and nothing beyond.
		topoAssertScopeWithin(t, "scope omitted", noScope.Scope(), true, "tools/echo")
		noRes := topoToken(t, f.h, topoCCForm("", "tools/echo"), topoAuthBasic, f.backend, f.secret)
		if !noRes.OK() {
			t.Fatalf("resource omitted: %d %s", noRes.Status, noRes.Raw)
		}
		if aud := topoAud(parseJWTClaims(t, noRes.AccessToken())); len(aud) != 1 || aud[0] != f.h.Issuer {
			t.Errorf("resource omitted: aud = %v, want [issuer %s] (documented default)", aud, f.h.Issuer)
		}
		mc := e2e.NewMCPClient(t, f.h, f.rs, f.backend, topoRedirect)
		if st, _ := mc.CallTool("/tools/echo", noRes.AccessToken(), `"x"`); st != http.StatusUnauthorized {
			t.Errorf("issuer-audienced token accepted by the RS: status %d", st)
		}
	})

	t.Run("BadAuthentication_RefusedAndAudited", func(t *testing.T) {
		t.Parallel()
		f := newM2MFixture(t)
		for _, auth := range topoBothAuth {
			if r := topoToken(t, f.h, topoCCForm(f.rs.URI, "tools/echo"), auth, f.backend, "wrong"); r.OK() || r.Err() != "invalid_client" || r.Status != http.StatusUnauthorized {
				t.Errorf("%s wrong secret: status %d error %q, want 401 invalid_client", auth, r.Status, r.Err())
			}
		}
		if r := topoToken(t, f.h, topoCCForm(f.rs.URI, "tools/echo"), topoAuthNone, f.backend, ""); r.OK() || r.Err() != "invalid_client" {
			t.Errorf("no secret: status %d error %q, want invalid_client", r.Status, r.Err())
		}
		// A public client may never use client_credentials.
		pub := f.h.AdminCreatePublicClient("public-cc", []string{"authorization_code"}, "tools/echo", nil)
		if r := topoToken(t, f.h, topoCCForm(f.rs.URI, "tools/echo"), topoAuthNone, pub, ""); r.OK() || r.Err() != "invalid_client" {
			t.Errorf("public client: status %d error %q, want invalid_client", r.Status, r.Err())
		}
		topoExpectAudit(t, f.h, "client_credentials.denied", "reason=invalid_client for the backend", func(r topoAuditRow) bool {
			return r.ClientID == f.backend && strings.Contains(r.Detail, "reason=invalid_client")
		})
	})

	t.Run("UnderPrivileged_CannotExceedRegisteredScopes", func(t *testing.T) {
		t.Parallel()
		f := newM2MFixture(t)
		r := topoToken(t, f.h, topoCCForm(f.rs.URI, "tools/echo tools/db_query"), topoAuthBasic, f.backend, f.secret)
		if r.OK() || r.Err() != "invalid_scope" {
			t.Errorf("scope beyond registration: status %d error %q, want invalid_scope", r.Status, r.Err())
		}
		// A client without the grant at all.
		noGrant, noGrantSecret := topoCreateClient(t, f.h, map[string]any{
			"client_name": "code-only", "grant_types": []string{"authorization_code"}, "response_types": []string{"code"},
			"token_endpoint_auth_method": "client_secret_basic", "scope": "tools/echo",
		})
		if r := topoToken(t, f.h, topoCCForm(f.rs.URI, "tools/echo"), topoAuthBasic, noGrant, noGrantSecret); r.OK() || r.Err() != "unauthorized_client" {
			t.Errorf("client without client_credentials: status %d error %q, want unauthorized_client", r.Status, r.Err())
		}
		topoExpectAudit(t, f.h, "client_credentials.denied", "reason=invalid_scope", func(r topoAuditRow) bool {
			return r.ClientID == f.backend && strings.Contains(r.Detail, "reason=invalid_scope")
		})
	})

	t.Run("UnknownResource_Refused", func(t *testing.T) {
		t.Parallel()
		f := newM2MFixture(t)
		r := topoToken(t, f.h, topoCCForm("https://not-registered.m2m.test", "tools/echo"), topoAuthBasic, f.backend, f.secret)
		if r.OK() {
			t.Fatalf("unregistered resource accepted: %s", r.Raw)
		}
		// RFC 8707 §2 names invalid_target for an unacceptable resource; the
		// auth-code and refresh paths already answer it.
		if r.Err() != "invalid_target" {
			t.Errorf("%s: unregistered resource on client_credentials: error %q, want invalid_target (RFC 8707 §2)", topoFindingPrefix, r.Err())
		}
	})

	// A client an operator registered for a different Resource (its scope is
	// that Resource's catalog) points its client_credentials request at this
	// one. The page's only authorization gate is "requested scope ⊆ the
	// client's scopes", so nothing ties the client to a Resource — the issued
	// token must at least never carry scopes the target does not declare.
	t.Run("ForeignClient_OtherResourcesScopeNeverLandsOnThisOne", func(t *testing.T) {
		t.Parallel()
		f := newM2MFixture(t)
		foreign, foreignSecret := topoCreateClient(t, f.h, map[string]any{
			"client_name": "metrics-emitter", "grant_types": []string{"client_credentials"},
			"token_endpoint_auth_method": "client_secret_basic", "scope": "emit",
		})
		for _, scope := range []string{"", "emit"} {
			r := topoToken(t, f.h, topoCCForm(f.rs.URI, scope), topoAuthBasic, foreign, foreignSecret)
			if !r.OK() {
				continue // refused: conforming
			}
			got := stringClaim(parseJWTClaims(t, r.AccessToken()), "scope")
			for _, s := range strings.Fields(got) {
				if s != "tools/echo" && s != "tools/db_query" {
					t.Errorf("%s: client registered for internal-metrics minted a token aud=%s carrying scope %q, which that resource does not declare (scope param %q)",
						topoFindingPrefix, f.rs.URI, s, scope)
				}
			}
		}
	})

	// Open DCR is the default (dcr.mode=open) and the concepts page says a
	// client registered there is user-delegated and "anonymous and
	// previously-arranged are contradictory" for client_credentials. An
	// anonymous registrant that asks for the grant anyway must not walk away
	// with a token audienced to a real Resource.
	t.Run("AnonymousDCRClient_CannotMintResourceTokens", func(t *testing.T) {
		t.Parallel()
		f := newM2MFixture(t)
		anon, anonSecret := topoDCR(t, f.h, map[string]any{
			"client_name": "drive-by", "grant_types": []string{"client_credentials"},
			"token_endpoint_auth_method": "client_secret_basic",
		})
		if r := topoToken(t, f.h, topoCCForm(f.rs.URI, "tools/echo"), topoAuthBasic, anon, anonSecret); r.OK() {
			t.Errorf("anonymous DCR client minted an explicit-scope token: %s", r.Raw)
		}
		r := topoToken(t, f.h, topoCCForm(f.rs.URI, ""), topoAuthBasic, anon, anonSecret)
		if r.OK() {
			aud := topoAud(parseJWTClaims(t, r.AccessToken()))
			t.Errorf("%s: anonymous DCR client (no operator involvement) minted a token aud=%v scope=%q by omitting scope; the scope-less ceiling is only enforced on explicit scope requests",
				topoFindingPrefix, aud, r.Scope())
		}
	})

	t.Run("RevocationReach_RevokeAndSuspend", func(t *testing.T) {
		t.Parallel()
		f := newM2MFixture(t)
		tok := topoToken(t, f.h, topoCCForm(f.rs.URI, "tools/echo"), topoAuthBasic, f.backend, f.secret)
		other := topoToken(t, f.h, topoCCForm(f.rs.URI, "tools/echo"), topoAuthPost, f.backend, f.secret)
		if !tok.OK() || !other.OK() {
			t.Fatal("precondition: mint two tokens")
		}
		if !f.h.IntrospectToken(tok.AccessToken(), f.rsID, f.rsSecret).Active {
			t.Fatal("precondition: token active")
		}
		// RFC 7009 revocation by the owner.
		if st := f.h.RevokeToken(tok.AccessToken(), f.backend, f.secret); st != http.StatusOK {
			t.Errorf("revoke: status %d", st)
		}
		if f.h.IntrospectToken(tok.AccessToken(), f.rsID, f.rsSecret).Active {
			t.Error("revoked machine token still active")
		}
		topoExpectAudit(t, f.h, "token.revoked", "for the machine token", func(r topoAuditRow) bool {
			return strings.Contains(r.Detail, "machine")
		})
		// Suspending the client reaches its live tokens and stops new mints.
		topoAdminPatch(t, f.h, "/admin/clients/"+f.backend+"/suspend")
		if f.h.IntrospectToken(other.AccessToken(), f.rsID, f.rsSecret).Active {
			t.Error("token of a suspended client still active")
		}
		if r := topoToken(t, f.h, topoCCForm(f.rs.URI, "tools/echo"), topoAuthBasic, f.backend, f.secret); r.OK() || r.Err() != "invalid_client" {
			t.Errorf("suspended client minted: status %d error %q", r.Status, r.Err())
		}
		topoExpectAudit(t, f.h, "client.suspended", "for the backend", func(r topoAuditRow) bool {
			return r.ClientID == f.backend
		})
	})
}
