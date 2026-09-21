package admin

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// SystemDeps holds optional system dependencies for admin system endpoints.
// The values these handlers write to the response are sanitized — no secrets,
// DSNs, or private key material reach the wire. Caveat: the OIDC field is a
// full OIDCConfigProvider whose OIDCConfig carries the upstream client secret;
// the only sanctioned read here is oidc.Enabled. Do not serialize more of that
// config from these handlers without re-checking for secret leakage.
type SystemDeps struct {
	// Process-global — static (no per-request provider).
	Version          string
	StartTime        time.Time
	DBPing           func(ctx context.Context) error
	StorageDriver    string
	KeyStoreDriver   string
	EncryptionDriver string
	SigningAlgorithm string
	RateLimitEnabled bool
	Audit            AuditRecorder

	// Per-request — resolved with r.Context() via the provider ports.
	Issuer            output.IssuerProvider
	DPoP              output.DPoPConfigProvider
	DCRMode           output.DCRModeProvider
	TokenExchange     output.TokenExchangeConfigProvider
	ClientCredentials output.ClientCredentialsConfigProvider
	Agents            output.AgentsConfigProvider
	// OIDC is a secret-bearing port (its OIDCConfig carries ClientSecret);
	// read only .Enabled here.
	OIDC output.OIDCConfigProvider
	// OAuth backs the operator notices. Its DefaultClientScope is a policy
	// value, not a secret — the notices report whether it is set, never what
	// it contains.
	OAuth output.OAuthConfigProvider
}

// systemHandler handles system status and configuration endpoints.
type systemHandler struct {
	deps *SystemDeps
	obs  *observability.Provider
}

// handleSystemStatus reports server health: version, uptime, and subsystem status.
func (h *systemHandler) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	subsystems := []subsystemStatus{
		{
			Name:   "storage",
			Driver: h.deps.StorageDriver,
			Status: h.pingStatus(r.Context()),
		},
		{
			Name:   "signing",
			Driver: h.deps.KeyStoreDriver,
			Status: "healthy",
		},
	}

	// Encryption subsystem.
	if h.deps.EncryptionDriver != "" {
		subsystems = append(subsystems, subsystemStatus{
			Name:   "encryption",
			Driver: h.deps.EncryptionDriver,
			Status: "healthy",
		})
	} else {
		subsystems = append(subsystems, subsystemStatus{
			Name:   "encryption",
			Status: "not_configured",
		})
	}

	uptime := time.Since(h.deps.StartTime)

	shared.WriteJSON(w, http.StatusOK, systemStatusResponse{
		Version:    h.deps.Version,
		Uptime:     formatDuration(uptime),
		UptimeSecs: int64(uptime.Seconds()),
		Subsystems: subsystems,
	})
}

// handleSystemConfig returns sanitized server configuration, resolving each
// feature flag per request via the provider ports. No secrets, DSNs, or private
// material — only driver names and feature flags. Any provider error is a 500:
// the report must not silently show a zero-value when resolution actually failed.
func (h *systemHandler) handleSystemConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	issuer, err := h.deps.Issuer.Issuer(ctx)
	if err != nil {
		h.configError(w, r, "resolve issuer", err)
		return
	}
	dpop, err := h.deps.DPoP.Config(ctx)
	if err != nil {
		h.configError(w, r, "resolve dpop config", err)
		return
	}
	tx, err := h.deps.TokenExchange.Config(ctx)
	if err != nil {
		h.configError(w, r, "resolve token-exchange config", err)
		return
	}
	cc, err := h.deps.ClientCredentials.Config(ctx)
	if err != nil {
		h.configError(w, r, "resolve client-credentials config", err)
		return
	}
	agents, err := h.deps.Agents.Config(ctx)
	if err != nil {
		h.configError(w, r, "resolve agents config", err)
		return
	}
	dcr, err := h.deps.DCRMode.Get(ctx)
	if err != nil {
		h.configError(w, r, "resolve dcr mode", err)
		return
	}
	oidc, err := h.deps.OIDC.Config(ctx)
	if err != nil {
		h.configError(w, r, "resolve oidc config", err)
		return
	}
	// Nil-tolerant, unlike its siblings: OAuth was added to an exported struct
	// that has no constructor, so an out-of-tree caller building a SystemDeps
	// literal still compiles and would otherwise panic here. Notices are
	// advisory, so degrading to none beats taking down /admin/system/config.
	//
	// Skipping the call entirely, not passing an empty scope: operatorNotices
	// cannot tell "not configured" from "no provider wired", so feeding it ""
	// would raise the "set oauth.default_client_scope" banner permanently at a
	// caller who may well have set it — an unclearable false alarm, which is
	// worse than the silence this is meant to degrade to.
	var notices []noticeView
	if h.deps.OAuth != nil {
		oauthCfg, oauthErr := h.deps.OAuth.Config(ctx)
		if oauthErr != nil {
			h.configError(w, r, "resolve oauth config", oauthErr)
			return
		}
		notices = operatorNotices(dcr.Mode, oauthCfg.DefaultClientScope)
	} else {
		notices = []noticeView{}
	}

	resp := systemConfigResponse{
		Issuer:            issuer,
		Storage:           storageConfigView{Driver: h.deps.StorageDriver},
		Signing:           signingConfigView{Algorithm: h.deps.SigningAlgorithm, KeyStore: h.deps.KeyStoreDriver},
		Encryption:        encryptionConfigView{Driver: h.deps.EncryptionDriver},
		DCR:               dcrConfigView{Mode: dcr.Mode},
		RateLimit:         rateLimitConfigView{Enabled: h.deps.RateLimitEnabled},
		ClientCredentials: clientCredentialsConfigView{Enabled: cc.Enabled},
		DPoP: dpopConfigView{
			Enabled:      dpop.Enabled,
			NonceTTL:     dpop.NonceTTL.String(),
			RequireNonce: dpop.RequireNonce,
		},
		TokenExchange: tokenExchangeConfigView{Enabled: tx.Enabled, MaxChainDepth: tx.MaxChainDepth},
		Agents:        agentsConfigView{Enabled: agents.AgentIdentityEnabled, JWKSListing: agents.EnableJWKSListing},
		OIDC:          oidcConfigView{Enabled: oidc.Enabled},
		Notices:       notices,
	}

	shared.WriteJSON(w, http.StatusOK, resp)
}

// configError logs a provider-resolution failure and writes a 500. The
// underlying error is never leaked on the wire.
func (h *systemHandler) configError(w http.ResponseWriter, r *http.Request, msg string, err error) {
	h.obs.Logger.ErrorContext(r.Context(), "system config: "+msg, "error", err)
	writeAdminError(w, http.StatusInternalServerError, "internal error")
}

// pingStatus pings the database and returns health status.
func (h *systemHandler) pingStatus(ctx context.Context) string {
	if h.deps.DBPing == nil {
		return "unknown"
	}
	if err := h.deps.DBPing(ctx); err != nil {
		h.obs.Logger.ErrorContext(ctx, "system status db ping failed", "error", err)
		return "unhealthy"
	}
	return "healthy"
}

// formatDuration formats a duration into a human-readable string.
func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// operatorNotices returns the advisories that apply to this deployment.
//
// Kept as a free function over plain values so the rules are unit-testable
// without standing up a handler, and so adding the next deprecation is a case
// here rather than a change to the response shape.
func operatorNotices(dcrMode, defaultClientScope string) []noticeView {
	// Never nil: the field is always present in the JSON, so a client can
	// render it without a null check.
	notices := []noticeView{}

	// dcr.mode gates both self-registration doors — CIMD refuses to
	// auto-register under admin_only too — so a closed deployment has nothing
	// to act on. "" is deliberately not in this set: config validation rejects
	// it and both registration services fail closed on an unrecognized mode,
	// so it registers nothing.
	selfRegistrationOpen := dcrMode == "open" || dcrMode == "approved_redirects"

	if selfRegistrationOpen && defaultClientScope == "" {
		notices = append(notices, noticeView{
			ID:       "oauth-default-client-scope-required-v0.3.0",
			Severity: "warning",
			Title:    "Set oauth.default_client_scope before v0.3.0",
			Body: "Clients that register themselves through dynamic registration or " +
				"CIMD cannot state their own scope ceiling, and this server has no " +
				"default to give them, so they are created without one. Their requests " +
				"are currently bounded only by the resource catalog. From v0.3.0 a " +
				"client with no ceiling will be refused at /oauth/authorize with " +
				"invalid_scope. Set oauth.default_client_scope " +
				"(AUTHPLANE_OAUTH_DEFAULT_CLIENT_SCOPE) to the scopes a self-registered " +
				"client may request. " +
				"Three groups it will not cover, each of which needs a scope set from " +
				"the Clients page: clients already registered, since the ceiling is " +
				"assigned once at registration time; clients created through the admin " +
				"API without a scope, since it is optional there; and self-registered " +
				"clients asking for client_credentials, jwt-bearer or token-exchange, " +
				"which are never given a ceiling by design. Closing dcr.mode stops new " +
				"ones being created and clears this notice, but fixes none of the three.",
			DocsURL: "https://docs.authplane.ai/reference/configuration",
		})
	}

	return notices
}
