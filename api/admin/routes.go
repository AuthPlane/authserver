package admin

import (
	"context"
	"net/http"

	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
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

// AuditRecorder records audit events. Matches services.AuditRecorder.
type AuditRecorder interface {
	Record(ctx context.Context, e audit.Event)
}

// registerRoutes wires all admin API route handlers on the mux.
func registerRoutes(mux *http.ServeMux, authMW *apiKeyMiddleware, admin Provider, obs *observability.Provider, systemDeps *SystemDeps, keysDeps *KeysDeps, dcrDeps *DCRDeps, xaaDeps *XAADeps, raDeps *ResourceAdminDeps, bpDeps *BrokerProviderAdminDeps, gaDeps *GrantAdminDeps, iaDeps *IssuanceAdminDeps, faDeps *FrontingAdminDeps) {
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
		xh := &xaaIDPHandler{
			idp: xaaDeps.IDP,
			obs: obs,
		}
		mux.Handle("POST /admin/idps", authMW.Wrap(http.HandlerFunc(xh.handleRegisterIDP)))
		mux.Handle("GET /admin/idps", authMW.Wrap(http.HandlerFunc(xh.handleListIDPs)))
		mux.Handle("GET /admin/idps/{id}", authMW.Wrap(http.HandlerFunc(xh.handleGetIDP)))
		mux.Handle("PUT /admin/idps/{id}", authMW.Wrap(http.HandlerFunc(xh.handleUpdateIDP)))
		mux.Handle("DELETE /admin/idps/{id}", authMW.Wrap(http.HandlerFunc(xh.handleDeleteIDP)))
		mux.Handle("POST /admin/idps/{id}/refresh-keys", authMW.Wrap(http.HandlerFunc(xh.handleRefreshKeys)))

		// XAA Policy routes.
		if xaaDeps.Policy != nil {
			ph := &xaaPolicyHandler{
				policy: xaaDeps.Policy,
				obs:    obs,
			}
			mux.Handle("POST /admin/xaa/policies", authMW.Wrap(http.HandlerFunc(ph.handleCreatePolicy)))
			mux.Handle("GET /admin/xaa/policies", authMW.Wrap(http.HandlerFunc(ph.handleListPolicies)))
			mux.Handle("GET /admin/xaa/policies/{id}", authMW.Wrap(http.HandlerFunc(ph.handleGetPolicy)))
			mux.Handle("PUT /admin/xaa/policies/{id}", authMW.Wrap(http.HandlerFunc(ph.handleUpdatePolicy)))
			mux.Handle("DELETE /admin/xaa/policies/{id}", authMW.Wrap(http.HandlerFunc(ph.handleDeletePolicy)))
		}

		// XAA Subject Mapping routes.
		if xaaDeps.SubjectMapping != nil {
			smh := &subjectMappingHandler{
				mapping: xaaDeps.SubjectMapping,
				obs:     obs,
			}
			mux.Handle("POST /admin/xaa/subject-mappings", authMW.Wrap(http.HandlerFunc(smh.handleCreateMapping)))
			mux.Handle("GET /admin/xaa/subject-mappings", authMW.Wrap(http.HandlerFunc(smh.handleListMappings)))
			mux.Handle("DELETE /admin/xaa/subject-mappings/{id}", authMW.Wrap(http.HandlerFunc(smh.handleDeleteMapping)))
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
}
