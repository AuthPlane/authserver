package admin

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// Provider is the local interface mirroring input.AdminPort.
type Provider interface {
	input.AdminPort
}

// ResourceAdminDeps holds optional unified-resource admin dependencies.
type ResourceAdminDeps struct {
	Resources input.ResourceAdminPort
}

// BrokerProviderAdminDeps holds optional broker-provider admin dependencies.
type BrokerProviderAdminDeps struct {
	BrokerProviders input.BrokerProviderAdminPort
}

// GrantAdminDeps holds optional grant-admin dependencies.
type GrantAdminDeps struct {
	Grants input.GrantAdminPort
}

// IssuanceAdminDeps holds optional issuance-admin dependencies.
type IssuanceAdminDeps struct {
	Issuances input.IssuanceAdminPort
}

// FrontingAdminDeps holds optional fronting-admin dependencies.
type FrontingAdminDeps struct {
	Fronting input.FrontingAdminPort
}

// ExtraRoute is one downstream-supplied admin route. Feature-agnostic: the
// server knows nothing about what the handler does. Registered on the same
// mux and behind the same auth wrapper as every built-in admin route.
type ExtraRoute struct {
	Pattern string // ServeMux pattern; its path must route under /admin/
	Handler http.Handler
}

// AuditRecorder records audit events. Matches services.AuditRecorder.
type AuditRecorder interface {
	Record(ctx context.Context, e audit.Event)
}

// registerRoutes wires all admin API route handlers on the mux. It returns an
// error when a downstream-supplied extra route is malformed (nil handler or a
// pattern outside /admin/), so the composition root decides how to fail rather
// than the package panicking. A pattern collision remains ServeMux's native
// panic — a wiring bug, like a collision among the built-in routes.
func registerRoutes(mux *http.ServeMux, authMW AuthWrapper, admin Provider, obs *observability.Provider, systemDeps *SystemDeps, keysDeps *KeysDeps, dcrDeps *DCRDeps, xaaDeps *XAADeps, raDeps *ResourceAdminDeps, bpDeps *BrokerProviderAdminDeps, gaDeps *GrantAdminDeps, iaDeps *IssuanceAdminDeps, faDeps *FrontingAdminDeps, extra []ExtraRoute) error {
	h := &handlers{admin: admin, obs: obs}

	// Client routes.
	mux.Handle("POST /admin/clients", authMW.Wrap(http.HandlerFunc(h.handleCreateClient)))
	mux.Handle("GET /admin/clients", authMW.Wrap(http.HandlerFunc(h.handleListClients)))
	mux.Handle("GET /admin/clients/{id}", authMW.Wrap(http.HandlerFunc(h.handleGetClient)))
	mux.Handle("PATCH /admin/clients/{id}", authMW.Wrap(http.HandlerFunc(h.handleUpdateClient)))
	mux.Handle("POST /admin/clients/{id}/rotate-secret", authMW.Wrap(http.HandlerFunc(h.handleRotateClientSecret)))
	mux.Handle("DELETE /admin/clients/{id}", authMW.Wrap(http.HandlerFunc(h.handleDeleteClient)))
	mux.Handle("PATCH /admin/clients/{id}/suspend", authMW.Wrap(http.HandlerFunc(h.handleSuspendClient)))
	mux.Handle("PATCH /admin/clients/{id}/revoke", authMW.Wrap(http.HandlerFunc(h.handleRevokeClient)))
	mux.Handle("PATCH /admin/clients/{id}/reactivate", authMW.Wrap(http.HandlerFunc(h.handleReactivateClient)))

	// Token routes.
	mux.Handle("GET /admin/tokens", authMW.Wrap(http.HandlerFunc(h.handleListTokens)))
	mux.Handle("DELETE /admin/tokens/{jti}", authMW.Wrap(http.HandlerFunc(h.handleRevokeToken)))

	// User routes.
	mux.Handle("GET /admin/users", authMW.Wrap(http.HandlerFunc(h.handleListUsers)))
	mux.Handle("POST /admin/users", authMW.Wrap(http.HandlerFunc(h.handleCreateUser)))
	mux.Handle("GET /admin/users/{id}", authMW.Wrap(http.HandlerFunc(h.handleGetUser)))
	mux.Handle("PATCH /admin/users/{id}", authMW.Wrap(http.HandlerFunc(h.handleUpdateUser)))
	mux.Handle("DELETE /admin/users/{id}", authMW.Wrap(http.HandlerFunc(h.handleDeleteUser)))
	mux.Handle("GET /admin/users/{id}/tokens", authMW.Wrap(http.HandlerFunc(h.handleListUserTokens)))
	mux.Handle("DELETE /admin/users/{id}/tokens", authMW.Wrap(http.HandlerFunc(h.handleForceLogoutUser)))
	mux.Handle("PATCH /admin/users/{id}/disable", authMW.Wrap(http.HandlerFunc(h.handleDisableUser)))
	mux.Handle("PATCH /admin/users/{id}/enable", authMW.Wrap(http.HandlerFunc(h.handleEnableUser)))

	// Audit route.
	mux.Handle("GET /admin/audit", authMW.Wrap(http.HandlerFunc(h.handleQueryAudit)))

	// Stats route.
	mux.Handle("GET /admin/stats", authMW.Wrap(http.HandlerFunc(h.handleGetStats)))

	// Auth verify + system routes (optional — require SystemDeps).
	if systemDeps != nil {
		ah := &authHandler{version: systemDeps.Version, audit: systemDeps.Audit, obs: obs}
		mux.Handle("POST /admin/auth/verify", authMW.Wrap(http.HandlerFunc(ah.handleAuthVerify)))

		sh := &systemHandler{deps: systemDeps, obs: obs}
		mux.Handle("GET /admin/system/status", authMW.Wrap(http.HandlerFunc(sh.handleSystemStatus)))
		mux.Handle("GET /admin/system/config", authMW.Wrap(http.HandlerFunc(sh.handleSystemConfig)))
	}

	// Key management routes (optional).
	if keysDeps != nil {
		kh := &keysAdminHandler{
			keyAdmin: keysDeps.KeyAdmin,
			audit:    keysDeps.Audit,
			obs:      obs,
		}
		mux.Handle("GET /admin/keys", authMW.Wrap(http.HandlerFunc(kh.handleListKeys)))
		mux.Handle("POST /admin/keys/rotate", authMW.Wrap(http.HandlerFunc(kh.handleRotateKey)))
	}

	// DCR settings routes (optional).
	if dcrDeps != nil {
		dh := &dcrSettingsHandler{
			dcr:      dcrDeps.DCR,
			settings: dcrDeps.Settings,
			audit:    dcrDeps.Audit,
			obs:      obs,
		}
		mux.Handle("GET /admin/settings/dcr", authMW.Wrap(http.HandlerFunc(dh.handleGetDCRSettings)))
		mux.Handle("PATCH /admin/settings/dcr", authMW.Wrap(http.HandlerFunc(dh.handleUpdateDCRSettings)))
	}

	// XAA (Enterprise-Managed Authorization) routes (optional).
	if xaaDeps != nil && xaaDeps.IDP != nil {
		// xaaGated applies the wrapping every XAA admin route shares: the auth
		// gate (outer) then the per-request feature gate on xaaDeps.Config.
		xaaGated := func(h http.HandlerFunc) http.Handler {
			return authMW.Wrap(xaaFeatureGate(xaaDeps.Config, obs, h))
		}

		xh := &xaaIDPHandler{
			idp: xaaDeps.IDP,
			obs: obs,
		}
		mux.Handle("POST /admin/idps", xaaGated(xh.handleRegisterIDP))
		mux.Handle("GET /admin/idps", xaaGated(xh.handleListIDPs))
		mux.Handle("GET /admin/idps/{id}", xaaGated(xh.handleGetIDP))
		mux.Handle("PUT /admin/idps/{id}", xaaGated(xh.handleUpdateIDP))
		mux.Handle("DELETE /admin/idps/{id}", xaaGated(xh.handleDeleteIDP))
		mux.Handle("POST /admin/idps/{id}/refresh-keys", xaaGated(xh.handleRefreshKeys))

		// XAA Policy routes.
		if xaaDeps.Policy != nil {
			ph := &xaaPolicyHandler{
				policy: xaaDeps.Policy,
				obs:    obs,
			}
			mux.Handle("POST /admin/xaa/policies", xaaGated(ph.handleCreatePolicy))
			mux.Handle("GET /admin/xaa/policies", xaaGated(ph.handleListPolicies))
			mux.Handle("GET /admin/xaa/policies/{id}", xaaGated(ph.handleGetPolicy))
			mux.Handle("PUT /admin/xaa/policies/{id}", xaaGated(ph.handleUpdatePolicy))
			mux.Handle("DELETE /admin/xaa/policies/{id}", xaaGated(ph.handleDeletePolicy))
		}

		// XAA Subject Mapping routes.
		if xaaDeps.SubjectMapping != nil {
			smh := &subjectMappingHandler{
				mapping: xaaDeps.SubjectMapping,
				obs:     obs,
			}
			mux.Handle("POST /admin/xaa/subject-mappings", xaaGated(smh.handleCreateMapping))
			mux.Handle("GET /admin/xaa/subject-mappings", xaaGated(smh.handleListMappings))
			mux.Handle("DELETE /admin/xaa/subject-mappings/{id}", xaaGated(smh.handleDeleteMapping))
		}
	}

	// Unified Resource admin routes (optional — the design).
	if raDeps != nil && raDeps.Resources != nil {
		rh := &resourceAdminHandler{
			svc: raDeps.Resources,
			obs: obs,
		}
		// Thread the broker provider port (when wired) so POST
		// /admin/resources accepts `broker_provider_slug`.
		// In every wiring path the two deps appear together; the
		// nil-check here is defensive.
		if bpDeps != nil && bpDeps.BrokerProviders != nil {
			rh.providers = bpDeps.BrokerProviders
		}
		mux.Handle("GET /admin/resources", authMW.Wrap(http.HandlerFunc(rh.handleList)))
		mux.Handle("POST /admin/resources", authMW.Wrap(http.HandlerFunc(rh.handleCreate)))
		mux.Handle("GET /admin/resources/{id}", authMW.Wrap(http.HandlerFunc(rh.handleGet)))
		mux.Handle("PATCH /admin/resources/{id}", authMW.Wrap(http.HandlerFunc(rh.handlePatch)))
		mux.Handle("DELETE /admin/resources/{id}", authMW.Wrap(http.HandlerFunc(rh.handleDelete)))

		// Per-policy-field endpoints. The path uses the
		// resource slug rather than the UUID — operators and bootstrap code
		// know their own slug, and forcing a list-and-translate dance is the
		// gap catalogs. Each mutation is atomic at the service
		// layer (read-modify-write inside one ResourceAdminService call) and
		// emits an audit row carrying the actor's intent.
		ph := &resourcePolicyAdminHandler{
			svc: raDeps.Resources,
			obs: obs,
		}
		mux.Handle("GET /admin/resources/{slug}/policy/exchange/allowed-clients", authMW.Wrap(http.HandlerFunc(ph.handleListAllowedClients)))
		mux.Handle("POST /admin/resources/{slug}/policy/exchange/allowed-clients", authMW.Wrap(http.HandlerFunc(ph.handleAddAllowedClient)))
		mux.Handle("DELETE /admin/resources/{slug}/policy/exchange/allowed-clients/{client_id}", authMW.Wrap(http.HandlerFunc(ph.handleRemoveAllowedClient)))
		mux.Handle("GET /admin/resources/{slug}/policy/connect/allowed-return-urls", authMW.Wrap(http.HandlerFunc(ph.handleListAllowedReturnURLs)))
		mux.Handle("POST /admin/resources/{slug}/policy/connect/allowed-return-urls", authMW.Wrap(http.HandlerFunc(ph.handleAddAllowedReturnURL)))
		mux.Handle("DELETE /admin/resources/{slug}/policy/connect/allowed-return-urls", authMW.Wrap(http.HandlerFunc(ph.handleRemoveAllowedReturnURL)))
		// runtime.client_ids — N:N linkage between OAuth clients and
		// the Resource(s) they may act AS at /oauth/token.
		mux.Handle("GET /admin/resources/{slug}/policy/runtime/client-ids", authMW.Wrap(http.HandlerFunc(ph.handleListRuntimeClientIDs)))
		mux.Handle("POST /admin/resources/{slug}/policy/runtime/client-ids", authMW.Wrap(http.HandlerFunc(ph.handleAddRuntimeClientID)))
		mux.Handle("DELETE /admin/resources/{slug}/policy/runtime/client-ids/{client_id}", authMW.Wrap(http.HandlerFunc(ph.handleRemoveRuntimeClientID)))
	}

	// Broker Provider admin routes (optional — the design).
	if bpDeps != nil && bpDeps.BrokerProviders != nil {
		bh := &brokerProviderAdminHandler{
			svc: bpDeps.BrokerProviders,
			obs: obs,
		}
		mux.Handle("GET /admin/broker-providers", authMW.Wrap(http.HandlerFunc(bh.handleList)))
		mux.Handle("POST /admin/broker-providers", authMW.Wrap(http.HandlerFunc(bh.handleCreate)))
		mux.Handle("GET /admin/broker-providers/{id}", authMW.Wrap(http.HandlerFunc(bh.handleGet)))
		mux.Handle("PATCH /admin/broker-providers/{id}", authMW.Wrap(http.HandlerFunc(bh.handlePatch)))
		mux.Handle("DELETE /admin/broker-providers/{id}", authMW.Wrap(http.HandlerFunc(bh.handleDelete)))
	}

	// Grant admin routes (optional — the design).
	if gaDeps != nil && gaDeps.Grants != nil {
		gh := &grantAdminHandler{
			svc: gaDeps.Grants,
			obs: obs,
		}
		mux.Handle("GET /admin/users/{id}/grants", authMW.Wrap(http.HandlerFunc(gh.handleListUserGrants)))
		mux.Handle("DELETE /admin/grants/consent/{id}", authMW.Wrap(http.HandlerFunc(gh.handleRevokeConsentGrant)))
		mux.Handle("DELETE /admin/grants/broker/{id}", authMW.Wrap(http.HandlerFunc(gh.handleRevokeBrokerGrant)))
	}

	// Issuance admin routes (optional — the design).
	if iaDeps != nil && iaDeps.Issuances != nil {
		ih := &issuanceAdminHandler{
			svc: iaDeps.Issuances,
			obs: obs,
		}
		mux.Handle("GET /admin/issuances", authMW.Wrap(http.HandlerFunc(ih.handleList)))
		mux.Handle("GET /admin/issuances/{id}", authMW.Wrap(http.HandlerFunc(ih.handleGet)))
		mux.Handle("DELETE /admin/issuances/{id}", authMW.Wrap(http.HandlerFunc(ih.handleRevoke)))
	}

	// Fronting link admin routes (optional — ). The per-Resource
	// convenience GET /admin/resources/{slug}/fronting is registered under
	// the fronting handler block (rather than the resourceAdminHandler one)
	// to keep both halves of the fronting surface in one wiring conditional.
	if faDeps != nil && faDeps.Fronting != nil {
		fh := &frontingAdminHandler{
			svc: faDeps.Fronting,
			obs: obs,
		}
		mux.Handle("GET /admin/fronting", authMW.Wrap(http.HandlerFunc(fh.handleList)))
		mux.Handle("POST /admin/fronting", authMW.Wrap(http.HandlerFunc(fh.handleCreate)))
		mux.Handle("GET /admin/fronting/{source}/{target}", authMW.Wrap(http.HandlerFunc(fh.handleGet)))
		mux.Handle("PATCH /admin/fronting/{source}/{target}", authMW.Wrap(http.HandlerFunc(fh.handlePatch)))
		mux.Handle("DELETE /admin/fronting/{source}/{target}", authMW.Wrap(http.HandlerFunc(fh.handleDelete)))
		mux.Handle("GET /admin/resources/{slug}/fronting", authMW.Wrap(http.HandlerFunc(fh.handleListForResource)))
	}

	// Extra routes supplied by a downstream build (optional).
	// Registered on the same mux with the same resolved auth wrapper as every
	// route above: an extra route inherits the sealed observability chain, the
	// rate limiter, and the auth gate, and cannot opt out (fail-closed). A
	// malformed route returns an error.
	//
	// Collision scope: only patterns of EQUAL specificity conflict, tripping
	// ServeMux's native panic at construction (e.g. an exact duplicate of a
	// built-in). A more-specific or subtree extra pattern does not conflict —
	// ServeMux precedence lets it coexist and win over a built-in wildcard
	// (e.g. GET /admin/clients/export shadows GET /admin/clients/{id}; GET
	// /admin/ or GET /admin/ui/x shadow their subtree). This is not caught and
	// not a fail-open — every extra route stays auth-gated; the downstream owns
	// its own patterns and is responsible for not shadowing built-ins.
	for _, er := range extra {
		if err := validateExtraRoute(er); err != nil {
			return err
		}
		mux.Handle(er.Pattern, authMW.Wrap(er.Handler))
	}
	return nil
}

// validateExtraRoute returns an error unless er is a well-formed extra admin
// route: non-nil handler and a pattern whose path routes under /admin/. Per the
// public ServeMux pattern grammar ("[METHOD ][HOST]/[PATH]"), trimming an
// optional whitespace-separated method prefix leaves the "[HOST]/[PATH]"; a
// host-bearing or empty pattern then fails the /admin/ prefix check, so the
// seam cannot shadow /metrics or any surface outside this server's admin
// namespace. It does not detect shadowing of a built-in route by a
// more-specific pattern (see the registration loop above).
func validateExtraRoute(er ExtraRoute) error {
	if er.Handler == nil {
		return fmt.Errorf("admin: extra route %q has a nil handler", er.Pattern)
	}
	path := er.Pattern
	if i := strings.IndexAny(path, " \t"); i >= 0 {
		path = strings.TrimLeft(path[i+1:], " \t")
	}
	if !strings.HasPrefix(path, "/admin/") {
		return fmt.Errorf("admin: extra route pattern %q must route under /admin/", er.Pattern)
	}
	return nil
}

// xaaFeatureGate wraps an XAA admin handler with a per-request feature check.
// A provider error is a 500 (cannot determine the feature state → fail closed);
// a resolved-off config is a typed 503 feature_disabled; a resolved-on config
// dispatches. The default static adapter never errors and reflects the boot
// config, so the 500/503 branches are inert in the default deployment.
func xaaFeatureGate(cfgp output.XAAConfigProvider, obs *observability.Provider, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A nil provider is a wiring error, not "feature off": fail closed with
		// 500 rather than nil-panic. The default binary always wires Config; this
		// guards a substitute deployment that mounts the routes (IDP set) but
		// leaves Config unset.
		if cfgp == nil {
			obs.Logger.ErrorContext(r.Context(), "xaa gate: nil config provider")
			writeAdminError(w, http.StatusInternalServerError, "internal error")
			return
		}
		cfg, err := cfgp.Config(r.Context())
		if err != nil {
			obs.Logger.ErrorContext(r.Context(), "xaa gate: resolve config", "error", err)
			writeAdminError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if !cfg.Enabled {
			fe := domain.NewFeatureDisabledError("xaa", "xaa.enabled")
			writeAdminError(w, http.StatusServiceUnavailable, fe.Error())
			return
		}
		next.ServeHTTP(w, r)
	})
}
