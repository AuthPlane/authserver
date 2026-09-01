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
