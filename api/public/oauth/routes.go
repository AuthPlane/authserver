package oauth

import (
	"context"
	"net/http"
	"time"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

// AuthorizeProvider handles the authorization code flow.
type AuthorizeProvider interface {
	StartAuthorization(ctx context.Context, req input.AuthorizeRequest) (*input.AuthorizeResult, error)
	CompleteAuthorization(ctx context.Context, sessionID string) (*input.CompleteAuthResult, error)
}

// TokenProvider handles token issuance.
type TokenProvider interface {
	ExchangeCode(ctx context.Context, req input.ExchangeCodeRequest) (*input.TokenResponse, error)
	RefreshToken(ctx context.Context, req input.RefreshTokenRequest) (*input.TokenResponse, error)
}

// RevocationProvider handles token revocation (RFC 7009).
type RevocationProvider interface {
	RevokeToken(ctx context.Context, req input.RevokeRequest) error
}

// DCRProvider handles Dynamic Client Registration and CIMD verification.
type DCRProvider interface {
	RegisterClient(ctx context.Context, req input.RegisterClientRequest) (*input.RegisterClientResponse, error)
}

// ClientCredentialsProvider handles the client_credentials grant (RFC 6749 §4.4).
type ClientCredentialsProvider interface {
	Exchange(ctx context.Context, req input.ClientCredentialsRequest) (*input.ClientCredentialsResponse, error)
}

// TokenExchangeProvider handles the token exchange grant (RFC 8693).
type TokenExchangeProvider interface {
	Exchange(ctx context.Context, req input.TokenExchangeRequest) (*input.TokenExchangeResponse, error)
}

// JWTBearerProvider handles the jwt-bearer grant (RFC 7523 / XAA).
type JWTBearerProvider interface {
	GrantJWTBearer(ctx context.Context, req input.JWTBearerRequest) (*input.JWTBearerResponse, error)
}

// IntrospectionProvider handles token introspection (RFC 7662).
type IntrospectionProvider interface {
	IntrospectToken(ctx context.Context, req input.IntrospectRequest) (*input.IntrospectResponse, error)
}

// UserAuthProvider is the local interface for user authentication.
type UserAuthProvider interface {
	Authenticate(ctx context.Context, email, password string) (*user.User, error)
}

// ConsentProvider handles consent display and approval/denial.
type ConsentProvider interface {
	GetPendingConsent(ctx context.Context, sessionID string) (*input.ConsentView, error)
	GrantConsent(ctx context.Context, req input.GrantConsentRequest) (*input.GrantConsentResult, error)
	DenyConsent(ctx context.Context, sessionID, userID string) error
}

// OIDCFlowProvider is the local interface for OIDC federation.
type OIDCFlowProvider interface {
	AuthorizationURL(state, nonce, codeChallenge, redirectURI string) string
	AuthenticateOIDC(ctx context.Context, code, nonce, codeVerifier, redirectURI string) (*user.User, error)
}

// Deps holds the dependencies for OAuth handlers.
type Deps struct {
	Authorize         AuthorizeProvider
	Token             TokenProvider
	ClientCredentials ClientCredentialsProvider // optional: nil if client_credentials disabled
	TokenExchange     TokenExchangeProvider     // optional: nil if token_exchange disabled
	JWTBearer         JWTBearerProvider         // optional: nil if jwt-bearer disabled
	Revoke            RevocationProvider
	DCR               DCRProvider
	Introspect        IntrospectionProvider
	DPoPNonce         DPoPNonceIssuer // optional: nil if DPoP disabled
	DPoPNonceTTL      time.Duration   // TTL for issued nonces
	// ConnectConsentBaseURL is the base URL used to build /connect/<provider>
	// consent_url values in ConsentRequiredError responses from the broker
	// vend path (bound-D / bound-E). Empty is allowed — the handler logs a
	// warn and emits consent_required without a consent_url (the JSON field
	// is omitted via omitempty).
	ConnectConsentBaseURL string
	// AuthorizeBaseURL is the AS issuer URL used to build
	// /authorize?resource=<slug>&scope=<scope> consent_url values for
	// AS-side re-consent flows (bound-B / bound-C, ). Empty is
	// allowed — same omit-with-warn semantics as ConnectConsentBaseURL.
	AuthorizeBaseURL string
}

// RegisterRoutes registers all OAuth routes on the mux.
func RegisterRoutes(mux *http.ServeMux, deps Deps, sessMW *shared.SessionMiddleware, rl *shared.RateLimiter, obs *observability.Provider) {
	// DCR endpoint.
	if deps.DCR != nil {
		rh := &registerHandler{dcr: deps.DCR, obs: obs}
		mux.HandleFunc("POST /oauth/register", rh.handleRegister)
	}

	// Authorization + token endpoints.
	if deps.Authorize != nil || deps.Token != nil || deps.ClientCredentials != nil || deps.TokenExchange != nil || deps.JWTBearer != nil {
		oh := &oauthHandler{
			authorize:          deps.Authorize,
			token:              deps.Token,
			clientCreds:        deps.ClientCredentials,
			tokenExchange:      deps.TokenExchange,
			jwtBearer:          deps.JWTBearer,
			session:            sessMW,
			obs:                obs,
			connectConsentBase: deps.ConnectConsentBaseURL,
			authorizeBase:      deps.AuthorizeBaseURL,
		}
		if deps.Authorize != nil {
			mux.Handle("GET /oauth/authorize", sessMW.Wrap(http.HandlerFunc(oh.handleAuthorize)))
		}

		if deps.Token != nil || deps.ClientCredentials != nil || deps.TokenExchange != nil || deps.JWTBearer != nil {
			var tokenHandler http.Handler = http.HandlerFunc(oh.handleToken)
			if deps.DPoPNonce != nil {
				tokenHandler = DPoPNonceMiddleware(deps.DPoPNonce, deps.DPoPNonceTTL)(tokenHandler)
			}
			mux.Handle("POST /oauth/token", tokenHandler)
		}
	}

	// Revocation endpoint.
	if deps.Revoke != nil {
		rh := &revokeHandler{revoke: deps.Revoke, obs: obs}
		mux.HandleFunc("POST /oauth/revoke", rh.handleRevoke)
	}

	// Introspection endpoint (RFC 7662).
	if deps.Introspect != nil {
		ih := &introspectHandler{introspect: deps.Introspect, obs: obs}
		mux.HandleFunc("POST /oauth/introspect", ih.handleIntrospect)
	}
}

// LoginDeps holds the dependencies for login/logout handlers.
type LoginDeps struct {
	Auth            UserAuthProvider
	OIDCDisplayName string // non-empty when OIDC upstream is configured
	ShowLocalLogin  bool   // show password form when OIDC is enabled (default true)
}

// RegisterLoginRoutes registers login/logout routes on the mux.
func RegisterLoginRoutes(mux *http.ServeMux, deps LoginDeps, sessMW *shared.SessionMiddleware, rl *shared.RateLimiter, obs *observability.Provider) {
	if deps.Auth == nil {
		return
	}

	lh := &loginHandler{
		auth:            deps.Auth,
		session:         sessMW,
		obs:             obs,
		rl:              rl,
		oidcDisplayName: deps.OIDCDisplayName,
		showLocalLogin:  deps.ShowLocalLogin,
	}
	mux.HandleFunc("GET /login", lh.handleGetLogin)
	mux.HandleFunc("POST /login", lh.handlePostLogin)
	mux.HandleFunc("POST /logout", lh.handlePostLogout)
}

// ConsentDeps holds the dependencies for consent handlers.
type ConsentDeps struct {
	Consent ConsentProvider
}

// RegisterConsentRoutes registers consent routes on the mux.
func RegisterConsentRoutes(mux *http.ServeMux, deps ConsentDeps, sessMW *shared.SessionMiddleware, obs *observability.Provider) {
	if deps.Consent == nil {
		return
	}

	ch := &consentHandler{
		consent: deps.Consent,
		session: sessMW,
		obs:     obs,
	}
	mux.Handle("GET /consent", sessMW.Wrap(http.HandlerFunc(ch.handleGetConsent)))
	mux.Handle("POST /consent", sessMW.Wrap(http.HandlerFunc(ch.handlePostConsent)))
}

// OIDCDeps holds the dependencies for OIDC handlers.
type OIDCDeps struct {
	OIDC        OIDCFlowProvider
	RedirectURI string // explicit redirect_uri from config
}

// RegisterOIDCRoutes registers OIDC upstream federation routes on the mux.
func RegisterOIDCRoutes(mux *http.ServeMux, deps OIDCDeps, sessMW *shared.SessionMiddleware, obs *observability.Provider) {
	if deps.OIDC == nil {
		return
	}

	oh := &oidcHandler{
		oidc:        deps.OIDC,
		session:     sessMW,
		obs:         obs,
		redirectURI: deps.RedirectURI,
		stateKey:    sessMW.DeriveKey("oidc-state"),
	}
	mux.HandleFunc("GET /oidc/start", oh.handleOIDCStart)
	mux.HandleFunc("GET /oidc/callback", oh.handleOIDCCallback)
}
