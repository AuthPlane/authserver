package admin

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/observability"
)

// SystemDeps holds optional system dependencies for admin system endpoints.
// All fields are sanitized — no secrets, DSNs, or private key material.
type SystemDeps struct {
	Version          string
	StartTime        time.Time
	DBPing           func(ctx context.Context) error
	StorageDriver    string
	KeyStoreDriver   string
	EncryptionDriver string
	SigningAlgorithm string
	Issuer           string
	Audit            AuditRecorder

	// Feature flags — sanitized, no secrets.
	ClientCredentialsEnabled bool
	DPoPEnabled              bool
	DPoPNonceTTL             string
	DPoPRequireNonce         bool
	TokenExchangeEnabled     bool
	TokenExchangeMaxChain    int
	AgentsEnabled            bool
	AgentsJWKSListing        bool
	OIDCEnabled              bool
	DCRMode                  string
	RateLimitEnabled         bool
	XAAEnabled               bool
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

// handleSystemConfig returns sanitized server configuration.
// No secrets, DSNs, or private material — only driver names and feature flags.
func (h *systemHandler) handleSystemConfig(w http.ResponseWriter, r *http.Request) {
	resp := systemConfigResponse{
		Issuer: h.deps.Issuer,
		Storage: storageConfigView{
			Driver: h.deps.StorageDriver,
		},
		Signing: signingConfigView{
			Algorithm: h.deps.SigningAlgorithm,
			KeyStore:  h.deps.KeyStoreDriver,
		},
		Encryption: encryptionConfigView{
			Driver: h.deps.EncryptionDriver,
		},
		DCR: dcrConfigView{
			Mode: h.deps.DCRMode,
		},
		RateLimit: rateLimitConfigView{
			Enabled: h.deps.RateLimitEnabled,
		},
		ClientCredentials: clientCredentialsConfigView{
			Enabled: h.deps.ClientCredentialsEnabled,
		},
		DPoP: dpopConfigView{
			Enabled:      h.deps.DPoPEnabled,
			NonceTTL:     h.deps.DPoPNonceTTL,
			RequireNonce: h.deps.DPoPRequireNonce,
		},
		TokenExchange: tokenExchangeConfigView{
			Enabled:       h.deps.TokenExchangeEnabled,
			MaxChainDepth: h.deps.TokenExchangeMaxChain,
		},
		Agents: agentsConfigView{
			Enabled:     h.deps.AgentsEnabled,
			JWKSListing: h.deps.AgentsJWKSListing,
		},
		OIDC: oidcConfigView{
			Enabled: h.deps.OIDCEnabled,
		},
	}

	shared.WriteJSON(w, http.StatusOK, resp)
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
