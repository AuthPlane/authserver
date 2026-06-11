package shared

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/observability"
)

const claimsKey contextKey = "jwtClaims"

// ClaimsFromContext returns the validated JWT access token claims from the request context.
func ClaimsFromContext(ctx context.Context) (*crypto.AccessTokenClaims, bool) {
	c, ok := ctx.Value(claimsKey).(*crypto.AccessTokenClaims)
	return c, ok
}

// JWKSProvider provides the JWKS key set for JWT verification.
type JWKSProvider interface {
	BuildJWKS(ctx context.Context) (*jose.JSONWebKeySet, error)
}

// DPoPJWTConfig holds optional DPoP configuration for the JWT middleware.
// When set, the middleware enforces DPoP proof-of-possession for DPoP-bound tokens.
type DPoPJWTConfig struct {
	ProofLifetime time.Duration // max |now - iat| for proof freshness
}

// DPoPProofStore records consumed DPoP proof JTIs for replay detection at the
// resource server. Mirrors output.DPoPNonceStore.ConsumeJTI so the existing
// SQLite/Postgres adapters can be passed in by the composition root.
type DPoPProofStore interface {
	ConsumeJTI(ctx context.Context, jti string, expiry time.Time) error
}

// JWTMiddleware validates Bearer (and optionally DPoP) JWT tokens and injects claims into context.
type JWTMiddleware struct {
	jwks       JWKSProvider
	issuer     string
	obs        *observability.Provider
	dpop       *DPoPJWTConfig // optional: nil means DPoP enforcement disabled
	audience   string         // optional: expected aud claim; empty disables audience check
	proofStore DPoPProofStore // optional: replay store for DPoP proof JTIs
}

// NewJWTMiddleware creates a JWT validation middleware suitable for
// authorization-server-internal endpoints (introspection, userinfo, etc.)
// where audience is not a meaningful gate. Resource servers MUST use
// NewResourceJWTMiddleware instead, which makes audience and DPoP proof
// storage non-optional and prevents the "I forgot WithAudience" footgun
// that the 2026-05-18 audit flagged.
func NewJWTMiddleware(jwks JWKSProvider, issuer string, obs *observability.Provider) *JWTMiddleware {
	return &JWTMiddleware{jwks: jwks, issuer: issuer, obs: obs}
}

// NewResourceJWTMiddleware creates a JWT validation middleware configured for
// a specific resource server. audience MUST be the resource URI (RFC 8707) and
// proofStore MUST be a replay store for DPoP proof JTIs — both are required
// because forgetting either re-opens the audience-confusion and DPoP-replay
// classes of bug, respectively. dpopCfg controls DPoP proof freshness; pass
// the zero value to disable DPoP enforcement for a Bearer-only resource.
//
// Panics if audience or proofStore is empty/nil — the failure mode of
// "I shipped a resource server with audience=\"\"" is precisely what this
// constructor exists to make impossible.
func NewResourceJWTMiddleware(
	jwks JWKSProvider,
	issuer, audience string,
	proofStore DPoPProofStore,
	dpopCfg DPoPJWTConfig,
	obs *observability.Provider,
) *JWTMiddleware {
	if audience == "" {
		panic("shared.NewResourceJWTMiddleware: audience is required for resource-server use (see api/shared/jwt_middleware.go and RFC 8707)")
	}
	if proofStore == nil {
		panic("shared.NewResourceJWTMiddleware: proofStore is required for resource-server use; pass DPoPNonceStore from the composition root (see audit 2026-05-18 MEDIUM finding on DPoP replay)")
	}
	m := &JWTMiddleware{
		jwks:       jwks,
		issuer:     issuer,
		obs:        obs,
		audience:   audience,
		proofStore: proofStore,
	}
	if dpopCfg.ProofLifetime > 0 {
		cfg := dpopCfg
		m.dpop = &cfg
	}
	return m
}

// WithDPoP enables DPoP proof-of-possession validation on the JWT middleware.
// When enabled, DPoP-bound tokens (containing cnf.jkt) require a valid DPoP proof.
func (m *JWTMiddleware) WithDPoP(cfg DPoPJWTConfig) *JWTMiddleware {
	m.dpop = &cfg
	return m
}

// WithAudience configures the expected audience (resource URI) for tokens
// accepted by this middleware. Once set, tokens whose `aud` claim does not
// contain `aud` are rejected with 401. Required for every resource-server
// deployment of this middleware (RFC 9068 §4, RFC 8707).
func (m *JWTMiddleware) WithAudience(aud string) *JWTMiddleware {
	m.audience = aud
	return m
}

// WithDPoPProofStore enables DPoP proof-JTI replay detection at the resource
// server. Without a store the middleware verifies the proof's structure and
// binding but does not consume the JTI, leaving a replay window equal to
// ProofLifetime. Required for any resource exposed to network attackers.
func (m *JWTMiddleware) WithDPoPProofStore(s DPoPProofStore) *JWTMiddleware {
	m.proofStore = s
	return m
}

// Wrap returns an http.Handler that validates the Bearer or DPoP JWT.
// On success, injects *crypto.AccessTokenClaims into context.
// On failure, returns 401 with WWW-Authenticate header.
func (m *JWTMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header (Bearer or DPoP scheme).
		rawToken, scheme := ExtractAuthToken(r)
		if rawToken == "" {
			// Fall back to legacy Bearer-only extraction for backward compatibility.
			rawToken = ExtractBearerToken(r)
			if rawToken != "" {
				scheme = "Bearer"
			}
		}

		if rawToken == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			if m.dpop != nil {
				w.Header().Add("WWW-Authenticate", "DPoP")
			}
			WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", "access token required")
			return
		}

		jwks, err := m.jwks.BuildJWKS(r.Context())
		if err != nil {
			m.obs.Logger.ErrorContext(r.Context(), "jwt middleware: failed to build JWKS", "error", err)
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", "token validation unavailable")
			return
		}

		claims, err := crypto.VerifyAccessTokenWithIssuer(rawToken, jwks, m.issuer)
		if err != nil {
			m.obs.Logger.DebugContext(r.Context(), "jwt middleware: token verification failed", "error", err)
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired token")
			return
		}

		// Audience enforcement (RFC 9068 §4, RFC 8707): when the middleware is
		// configured with an expected audience, the token's `aud` must contain
		// it. A token minted for resource A must not be honored by resource B
		// — this is the load-bearing per-resource isolation check. If no
		// audience is configured the middleware preserves the prior
		// issuer-only behavior for backward compatibility with the e2e
		// fixture; new deployments MUST call WithAudience.
		if m.audience != "" && !claims.HasAudience(m.audience) {
			m.obs.Logger.DebugContext(r.Context(), "jwt middleware: audience mismatch",
				"expected", m.audience, "got", claims.Audience)
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="audience mismatch"`)
			WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", "token audience does not match this resource")
			return
		}

		// DPoP enforcement: if token has cnf.jkt, it's DPoP-bound (RFC 9449 §7.1).
		if crypto.IsDPoPBound(claims) {
			if err := m.validateDPoPBinding(r, rawToken, claims, scheme); err != nil {
				m.obs.Logger.DebugContext(r.Context(), "jwt middleware: DPoP binding validation failed", "error", err)
				w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token", error_description="DPoP proof required"`)
				WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", err.Error())
				return
			}
		}

		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// validateDPoPBinding validates DPoP proof-of-possession for a DPoP-bound access token.
func (m *JWTMiddleware) validateDPoPBinding(r *http.Request, rawToken string, claims *crypto.AccessTokenClaims, scheme string) error {
	// DPoP-bound tokens MUST use the DPoP scheme, not Bearer (RFC 9449 §7.1).
	if scheme != "DPoP" {
		return fmt.Errorf("DPoP-bound token must use DPoP authorization scheme")
	}

	// DPoP proof header is required.
	dpopProof := r.Header.Get("DPoP")
	if dpopProof == "" {
		return fmt.Errorf("DPoP proof header required for DPoP-bound token")
	}

	// Compute ath (access token hash) — base64url(SHA-256(access_token)).
	ath := crypto.ComputeATH(rawToken)

	proofLifetime := 60 * time.Second
	if m.dpop != nil {
		proofLifetime = m.dpop.ProofLifetime
	}

	// Reconstruct request URL for htu validation.
	reqURL := RequestURL(r)

	result, err := crypto.ValidateProof(dpopProof, r.Method, reqURL, "", ath, proofLifetime)
	if err != nil {
		return fmt.Errorf("DPoP proof validation failed: %w", err)
	}

	// Verify that the proof's JKT matches the token's cnf.jkt. We do this
	// BEFORE consuming the JTI so that an attacker with a proof signed by the
	// wrong key cannot burn legitimate JTIs in the store.
	expectedJKT, _ := claims.Cnf["jkt"].(string)
	if result.JKT != expectedJKT {
		return fmt.Errorf("DPoP proof key does not match token binding")
	}

	// Consume the proof JTI for replay detection. Without this the binding is
	// verified per-request but a captured proof can be replayed against the
	// same method/URL within ProofLifetime. The token endpoint already
	// consumes via dpopStore.ConsumeJTI; this mirrors that at the resource
	// server. If no store is configured the middleware logs and continues —
	// existing e2e tests run without a store.
	if m.proofStore != nil {
		expiry := time.Now().Add(proofLifetime * 2)
		if storeErr := m.proofStore.ConsumeJTI(r.Context(), result.JTI, expiry); storeErr != nil {
			return fmt.Errorf("DPoP proof replay detected: %w", storeErr)
		}
	}

	return nil
}
