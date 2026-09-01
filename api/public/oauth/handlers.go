// Package oauth provides OAuth authorization and token HTTP handlers.
package oauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	connectionapi "github.com/authplane/authserver/api/public/connection"
	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// oauthHandler handles GET /oauth/authorize and POST /oauth/token.
type oauthHandler struct {
	authorize     AuthorizeProvider
	token         TokenProvider
	clientCreds   ClientCredentialsProvider
	tokenExchange TokenExchangeProvider
	jwtBearer     JWTBearerProvider
	session       *shared.SessionMiddleware
	obs           *observability.Provider
	urls          output.URLBuilder
	// issuerProvider resolves the AS issuer URL — the public base for
	// everything under the host (<issuer>/authorize, <issuer>/connect/<provider>,
	// <issuer>/connections). Both consent_required URL flavors are built
	// from it. Optional: when nil (or it resolves empty) the handler emits
	// consent_required without a consent_url.
	issuerProvider output.IssuerProvider
}

// handleAuthorize handles GET /oauth/authorize.
func (h *oauthHandler) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Extract user ID from session middleware context.
	userID, _ := shared.UserIDFromContext(r.Context())

	req := input.AuthorizeRequest{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		ResponseType:        q.Get("response_type"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		Resource:            q.Get("resource"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		UserID:              userID,
	}

	result, err := h.authorize.StartAuthorization(r.Context(), req)
	if err != nil {
		h.handleAuthorizeError(w, r, req, err)
		return
	}

	// Login required: redirect to login page, preserving the full authorize URL.
	if result.LoginRequired {
		loginURL := fmt.Sprintf("/login?redirect=%s", url.QueryEscape(r.URL.String()))
		shared.RedirectInternal(w, r, h.urls, loginURL, http.StatusSeeOther, h.obs.Logger)
		return
	}

	// Consent required: redirect to consent page.
	if result.ConsentRequired {
		consentURL := fmt.Sprintf("/consent?session_id=%s", url.QueryEscape(result.Session.ID))
		shared.RedirectInternal(w, r, h.urls, consentURL, http.StatusSeeOther, h.obs.Logger)
		return
	}

	// Neither login nor consent required -- complete immediately.
	completed, err := h.authorize.CompleteAuthorization(r.Context(), result.Session.ID)
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(), "complete authorization failed", "error", err)
		redirectWithError(w, r, req.RedirectURI, req.State, "server_error", "authorization failed")
		return
	}

	redirectWithCode(w, r, completed.RedirectURI, completed.Code, completed.State)
}

// handleAuthorizeError routes authorization errors correctly:
// - Invalid client_id or redirect_uri -> render error page (never redirect to attacker URI)
// - All other errors -> redirect to redirect_uri with error params
func (h *oauthHandler) handleAuthorizeError(w http.ResponseWriter, r *http.Request, req input.AuthorizeRequest, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidClient):
		shared.WriteErrorPage(w, r, http.StatusBadRequest, "Invalid Client", "The client_id is not recognized.")
	case errors.Is(err, domain.ErrInvalidRedirectURI):
		shared.WriteErrorPage(w, r, http.StatusBadRequest, "Invalid Redirect URI", "The redirect_uri does not match the client registration.")
	case errors.Is(err, domain.ErrClientSuspended):
		shared.WriteErrorPage(w, r, http.StatusForbidden, "Client Suspended", "This client has been suspended.")
	case errors.Is(err, domain.ErrInvalidGrant):
		shared.WriteErrorPage(w, r, http.StatusBadRequest, "Authorization Error", "The requested grant type or response type is not supported.")
	case errors.Is(err, domain.ErrConsentResourceNotMint):
		shared.WriteErrorPage(w, r, http.StatusBadRequest, "Invalid Resource", "Consent is only available for MCP resources, not upstream broker resources.")
	case errors.Is(err, domain.ErrResourceNotFound):
		shared.WriteErrorPage(w, r, http.StatusBadRequest, "Unknown Resource", "The requested resource is not registered with this authorization server.")
	case errors.Is(err, domain.ErrAmbiguousResource):
		shared.WriteErrorPage(w, r, http.StatusBadRequest, "Ambiguous Resource", "The resource identifier matches more than one resource. Use the resource slug to disambiguate.")
	default:
		if req.RedirectURI != "" {
			code := domain.ErrorCode(err)
			desc := err.Error()
			if !domain.IsError(err) {
				h.obs.Logger.ErrorContext(r.Context(), "authorize error", "error", err)
				code = "server_error"
				desc = "an internal error occurred"
			}
			redirectWithError(w, r, req.RedirectURI, req.State, code, desc)
			return
		}
		desc := err.Error()
		if !domain.IsError(err) {
			h.obs.Logger.ErrorContext(r.Context(), "authorize error", "error", err)
			desc = "an internal error occurred"
		}
		shared.WriteErrorPage(w, r, http.StatusBadRequest, "Authorization Error", desc)
	}
}

// handleToken handles POST /oauth/token.
func (h *oauthHandler) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64KB
	if err := r.ParseForm(); err != nil {
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthCodeExchange(w, r)
	case "refresh_token":
		h.handleRefreshToken(w, r)
	case "client_credentials":
		h.handleClientCredentials(w, r)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		h.handleTokenExchange(w, r)
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":
		h.handleJWTBearer(w, r)
	default:
		shared.WriteOAuthError(w, http.StatusBadRequest, "unsupported_grant_type",
			fmt.Sprintf("grant_type %q is not supported", grantType))
	}
}

func (h *oauthHandler) handleAuthCodeExchange(w http.ResponseWriter, r *http.Request) {
	if h.token == nil {
		shared.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "token service not configured")
		return
	}

	clientID, clientSecret := ExtractClientAuth(r)
	dpopProof, dpopMethod, dpopURL := extractDPoPInfo(r)

	req := input.ExchangeCodeRequest{
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		CodeVerifier: r.FormValue("code_verifier"),
		DPoPProof:    dpopProof,
		HTTPMethod:   dpopMethod,
		HTTPURL:      dpopURL,
	}

	resp, err := h.token.ExchangeCode(r.Context(), req)
	if err != nil {
		h.writeTokenError(w, r, err)
		return
	}

	writeTokenResponse(w, resp)
}

func (h *oauthHandler) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	if h.token == nil {
		shared.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "token service not configured")
		return
	}

	clientID, clientSecret := ExtractClientAuth(r)
	dpopProof, dpopMethod, dpopURL := extractDPoPInfo(r)

	req := input.RefreshTokenRequest{
		RefreshToken: r.FormValue("refresh_token"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        r.FormValue("scope"),
		DPoPProof:    dpopProof,
		HTTPMethod:   dpopMethod,
		HTTPURL:      dpopURL,
	}

	resp, err := h.token.RefreshToken(r.Context(), req)
	if err != nil {
		h.writeTokenError(w, r, err)
		return
	}

	writeTokenResponse(w, resp)
}

func (h *oauthHandler) handleClientCredentials(w http.ResponseWriter, r *http.Request) {
	if h.clientCreds == nil {
		// name the config key so operators don't have to grep the
		// codebase to find which flag re-enables the grant.
		err := domain.NewFeatureDisabledError("client_credentials", "client_credentials.enabled=true")
		shared.WriteOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", err.Error())
		return
	}

	clientID, clientSecret := ExtractClientAuth(r)
	dpopProof, dpopMethod, dpopURL := extractDPoPInfo(r)

	req := input.ClientCredentialsRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        r.FormValue("scope"),
		Resource:     r.FormValue("resource"),
		DPoPProof:    dpopProof,
		HTTPMethod:   dpopMethod,
		HTTPURL:      dpopURL,
	}

	resp, err := h.clientCreds.Exchange(r.Context(), req)
	if err != nil {
		h.writeTokenError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(tokenResponseDTO{
		AccessToken: resp.AccessToken,
		TokenType:   resp.TokenType,
		ExpiresIn:   resp.ExpiresIn,
		Scope:       resp.Scope,
		// No refresh_token for client_credentials.
	})
}

func (h *oauthHandler) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	if h.tokenExchange == nil {
		err := domain.NewFeatureDisabledError("token_exchange", "token_exchange.enabled=true")
		shared.WriteOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", err.Error())
		return
	}

	clientID, clientSecret := ExtractClientAuth(r)
	dpopProof, dpopMethod, dpopURL := extractDPoPInfo(r)

	req := input.TokenExchangeRequest{
		SubjectToken:     r.FormValue("subject_token"),
		SubjectTokenType: r.FormValue("subject_token_type"),
		ActorToken:       r.FormValue("actor_token"),
		ActorTokenType:   r.FormValue("actor_token_type"),
		Scope:            r.FormValue("scope"),
		Resource:         r.FormValue("resource"),
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		DPoPProof:        dpopProof,
		HTTPMethod:       dpopMethod,
		HTTPURL:          dpopURL,
	}

	resp, err := h.tokenExchange.Exchange(r.Context(), req)
	if err != nil {
		h.writeTokenError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(tokenExchangeResponseDTO{
		AccessToken:     resp.AccessToken,
		IssuedTokenType: resp.IssuedTokenType,
		TokenType:       resp.TokenType,
		ExpiresIn:       resp.ExpiresIn,
		Scope:           resp.Scope,
	})
}

func (h *oauthHandler) handleJWTBearer(w http.ResponseWriter, r *http.Request) {
	if h.jwtBearer == nil {
		err := domain.NewFeatureDisabledError("jwt_bearer", "xaa.enabled=true")
		shared.WriteOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", err.Error())
		return
	}

	clientID, clientSecret := ExtractClientAuth(r)
	dpopProof, dpopMethod, dpopURL := extractDPoPInfo(r)

	req := input.JWTBearerRequest{
		Assertion:    r.FormValue("assertion"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        r.FormValue("scope"),
		Resource:     r.FormValue("resource"),
		DPoPProof:    dpopProof,
		HTTPMethod:   dpopMethod,
		HTTPURL:      dpopURL,
	}

	resp, err := h.jwtBearer.GrantJWTBearer(r.Context(), req)
	if err != nil {
		h.writeTokenError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(tokenResponseDTO{
		AccessToken: resp.AccessToken,
		TokenType:   resp.TokenType,
		ExpiresIn:   resp.ExpiresIn,
		Scope:       resp.Scope,
		// No refresh_token for jwt-bearer.
	})
}

func (h *oauthHandler) writeTokenError(w http.ResponseWriter, r *http.Request, err error) {
	// structured consent_required error for vault-backed
	// upstream services. The service layer emits a ConsentRequiredError
	// carrying only the service slug; the consent URL is built here at
	// serialization time so service-layer code stays free of transport
	// concerns. Must be checked before the generic switch below because
	// ConsentRequiredError also satisfies domain.Error.
	var consentErr *domain.ConsentRequiredError
	if errors.As(err, &consentErr) {
		// Pick the consent_url flavor based on (Cause, ProviderSlug):
		//   - ProviderSlug populated → upstream-OAuth re-connect URL
		//     (/connect/<provider>) — bound-D (no broker_grants row) or
		//     bound-E (broker_grants scope-insufficient) failures.
		//   - ProviderSlug empty + ResourceSlug populated → AS-side
		//     re-consent URL (/authorize?resource=<slug>&scope=<scope>)
		//     — bound-B (agent-attestation row missing) or bound-C
		//     (agent-attestation scope-insufficient) failures.
		//   - Both empty → no consent_url; client shows the generic
		//     consent_required error.
		// Both consent_url flavors derive from the issuer — the public base
		// for everything under the host. Resolve it once; on failure (or an
		// empty value) fall through to the graceful-omit warn below rather
		// than failing the token response.
		issuerBase := ""
		var issuerErr error
		if h.issuerProvider != nil {
			issuerBase, issuerErr = h.issuerProvider.Issuer(r.Context())
		}
		var consentURL string
		switch {
		case issuerErr != nil:
			h.obs.Logger.WarnContext(r.Context(),
				"emitting consent_required without consent_url — issuer could not be resolved",
				"error", issuerErr,
				"provider_slug", consentErr.ProviderSlug,
				"resource_slug", consentErr.ResourceSlug,
			)
		case consentErr.ProviderSlug != "":
			consentURL = connectionapi.ConsentURL(issuerBase, consentErr.ProviderSlug, consentErr.ResourceSlug)
			if consentURL == "" {
				h.obs.Logger.WarnContext(r.Context(),
					"emitting consent_required without consent_url — issuer is not configured",
					"provider_slug", consentErr.ProviderSlug,
					"resource_slug", consentErr.ResourceSlug,
				)
			}
		case consentErr.ResourceSlug != "":
			scope := ""
			if consentErr.Cause == domain.CauseScopeInsufficient {
				scope = strings.Join(consentErr.MissingScopes, " ")
			}
			consentURL = connectionapi.ReconsentURL(issuerBase, consentErr.ResourceSlug, scope)
			if consentURL == "" {
				h.obs.Logger.WarnContext(r.Context(),
					"emitting consent_required without consent_url — issuer is not configured",
					"resource_slug", consentErr.ResourceSlug,
				)
			}
		}
		// Cause defaults to consent_missing on the wire when the error
		// originated previously (empty Cause); explicit values flow through.
		cause := consentErr.Cause
		if cause == "" {
			cause = domain.CauseConsentMissing
		}
		shared.WriteOAuthErrorWithConsentAndCause(w, http.StatusBadRequest,
			"consent_required", consentErr.Error(), consentURL, cause)
		return
	}

	switch {
	case errors.Is(err, domain.ErrInvalidClient),
		errors.Is(err, domain.ErrClientSuspended):
		w.Header().Set("WWW-Authenticate", `Basic realm="authserver"`)
		shared.WriteOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
	case errors.Is(err, domain.ErrUnauthorizedClient):
		shared.WriteOAuthError(w, http.StatusBadRequest, "unauthorized_client", err.Error())
	case errors.Is(err, domain.ErrCodeConsumed),
		errors.Is(err, domain.ErrInvalidGrant),
		errors.Is(err, domain.ErrSessionExpired),
		errors.Is(err, domain.ErrFamilyRevoked),
		errors.Is(err, domain.ErrReuseRevocationFailed):
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
	case errors.Is(err, domain.ErrInvalidPKCE):
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
	case errors.Is(err, domain.ErrInvalidScope):
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_scope", err.Error())
	case errors.Is(err, domain.ErrUnsupportedGrantType):
		shared.WriteOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", err.Error())
	case errors.Is(err, domain.ErrDPoPInvalidProof),
		errors.Is(err, domain.ErrDPoPReplay):
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_dpop_proof", err.Error())
	case errors.Is(err, domain.ErrDPoPNonceRequired),
		errors.Is(err, domain.ErrDPoPNonceMismatch):
		// DPoP-Nonce header is set by the DPoPNonceMiddleware (RFC 9449 §8).
		shared.WriteOAuthError(w, http.StatusBadRequest, "use_dpop_nonce", err.Error())
	case errors.Is(err, domain.ErrTokenExchangeNotAuthorized):
		shared.WriteOAuthError(w, http.StatusForbidden, "access_denied", err.Error())
	case errors.Is(err, domain.ErrTokenExchangeChainTooDeep):
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
	case errors.Is(err, domain.ErrAssertionInvalid),
		errors.Is(err, domain.ErrAssertionExpired),
		errors.Is(err, domain.ErrAssertionIssuerUntrusted),
		errors.Is(err, domain.ErrAssertionAudienceMismatch),
		errors.Is(err, domain.ErrAssertionTypeMismatch),
		errors.Is(err, domain.ErrAssertionReplay),
		errors.Is(err, domain.ErrIDPDisabled):
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
	case errors.Is(err, domain.ErrAssertionClientMismatch):
		w.Header().Set("WWW-Authenticate", `Basic realm="authserver"`)
		shared.WriteOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
	case errors.Is(err, domain.ErrAssertionPolicyDenied):
		shared.WriteOAuthError(w, http.StatusForbidden, "access_denied", err.Error())
	case domain.IsError(err):
		shared.WriteOAuthError(w, http.StatusBadRequest, domain.ErrorCode(err), err.Error())
	default:
		h.obs.Logger.ErrorContext(r.Context(), "token endpoint error", "error", err)
		shared.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
	}
}

// ExtractClientAuth extracts client credentials from Basic auth header or form body.
func ExtractClientAuth(r *http.Request) (clientID, clientSecret string) {
	// Try Authorization: Basic header first.
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(auth[6:])
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				id, idErr := url.QueryUnescape(parts[0])
				sec, secErr := url.QueryUnescape(parts[1])
				if idErr != nil || secErr != nil {
					return "", ""
				}
				return id, sec
			}
		}
	}

	// Fall back to form body.
	return r.FormValue("client_id"), r.FormValue("client_secret")
}

func writeTokenResponse(w http.ResponseWriter, resp *input.TokenResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(tokenResponseDTO{
		AccessToken:  resp.AccessToken,
		TokenType:    resp.TokenType,
		ExpiresIn:    resp.ExpiresIn,
		RefreshToken: resp.RefreshToken,
		Scope:        resp.Scope,
	})
}

func redirectWithCode(w http.ResponseWriter, r *http.Request, redirectURI, code, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		shared.WriteErrorPage(w, r, http.StatusInternalServerError, "Error", "Invalid redirect URI")
		return
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

// extractDPoPInfo extracts DPoP proof and request context from the HTTP request.
// Returns empty strings if no DPoP header is present.
func extractDPoPInfo(r *http.Request) (proof, method, reqURL string) {
	proof = r.Header.Get("DPoP")
	if proof == "" {
		return "", "", ""
	}
	return proof, r.Method, shared.RequestURL(r)
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, description string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		shared.WriteErrorPage(w, r, http.StatusInternalServerError, "Error", "Invalid redirect URI")
		return
	}
	q := u.Query()
	q.Set("error", errCode)
	q.Set("error_description", description)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

// --- Revocation handler ---

// revokeHandler handles POST /oauth/revoke (RFC 7009).
type revokeHandler struct {
	revoke RevocationProvider
	obs    *observability.Provider
}

func (h *revokeHandler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64KB
	if err := r.ParseForm(); err != nil {
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}

	token := r.FormValue("token")
	if token == "" {
		shared.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "token parameter is required")
		return
	}

	clientID, clientSecret := ExtractClientAuth(r)

	req := input.RevokeRequest{
		Token:         token,
		TokenTypeHint: r.FormValue("token_type_hint"),
		ClientID:      clientID,
		ClientSecret:  clientSecret,
	}

	err := h.revoke.RevokeToken(r.Context(), req)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidClient) {
			w.Header().Set("WWW-Authenticate", `Basic realm="authserver"`)
			shared.WriteOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
			return
		}
		h.obs.Logger.ErrorContext(r.Context(), "revocation error", "error", err)
	}

	// Per RFC 7009: always return 200 for valid token revocations.
	w.WriteHeader(http.StatusOK)
}
