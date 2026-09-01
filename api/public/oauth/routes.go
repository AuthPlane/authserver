package oauth

import (
	"context"
	"net/http"
	"time"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
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
//
// ERROR CONTRACT — the login handler gates the account lockout on it, so an
// implementation that ignores this silently disables a security control.
//
// A rejected credential MUST be reported as an error satisfying
// errors.Is(err, domain.ErrInvalidCredentials). That is the only error class
// counted toward the lockout, and the only one rendered as "invalid email or
// password".
//
// Any other non-nil error is read as "this side failed" and answers 500 without
// counting anything. That split exists because counting a store failure locks
// out every user who retried through a database outage — for the full
// auth_lockout, after the database recovers, with auth.locked_out audit rows
// describing an outage as an attack.
//
// The consequence of getting it wrong is quiet: an implementation returning its
// own sentinel for a wrong password compiles, answers 500 on every failed
// login, and never engages the lockout. Nothing fails loudly. If that trade
// bites, the durable fix is to carry the classification in the signature rather
// than in a sentinel this interface merely describes.
type UserAuthProvider interface {
	Authenticate(ctx context.Context, email, password string) (*user.User, error)
}

// ConsentProvider handles consent display and approval/denial.
type ConsentProvider interface {
	GetPendingConsent(ctx context.Context, sessionID string) (*input.ConsentView, error)
	GrantConsent(ctx context.Context, req input.GrantConsentRequest) (*input.GrantConsentResult, error)
	DenyConsent(ctx context.Context, sessionID, userID string) error
}

// AuditRecorder records security audit events. Matches services.AuditRecorder,
// restated here so api/ does not import internal/services (see the Makefile's
// check-imports target). Recording is best-effort and never fails a request.
type AuditRecorder interface {
	Record(ctx context.Context, e audit.Event)
}

// OIDCFlowProvider is the local interface for OIDC federation.
type OIDCFlowProvider interface {
	AuthorizationURL(ctx context.Context, state, nonce, codeChallenge string) (string, error)
	AuthenticateOIDC(ctx context.Context, code, nonce, codeVerifier string) (*user.User, error)
}

// Deps holds the dependencies for OAuth handlers.
type Deps struct {
	Authorize         AuthorizeProvider
	URLs              output.URLBuilder
	Token             TokenProvider
	ClientCredentials ClientCredentialsProvider // optional: nil if client_credentials disabled
	TokenExchange     TokenExchangeProvider     // optional: nil if token_exchange disabled
	JWTBearer         JWTBearerProvider         // optional: nil if jwt-bearer disabled
	Revoke            RevocationProvider
	DCR               DCRProvider
	Introspect        IntrospectionProvider
	// OAuthConfig gates POST /oauth/introspect at runtime via
	// IntrospectionEnabled, from the same source as the discovery document's
	// introspection_endpoint. Optional — when nil the endpoint is always served
	// (pre-seam behavior).
	OAuthConfig  output.OAuthConfigProvider
	DPoPNonce    DPoPNonceIssuer // optional: nil if DPoP disabled
	DPoPNonceTTL time.Duration   // TTL for issued nonces
	// IssuerProvider resolves the AS issuer URL — the public base for
	// everything under the host. Both consent_url flavors in
	// consent_required responses are built from it: the broker upstream
	// re-connect URL (/connect/<provider>, bound-D / bound-E) and the
	// AS-side re-consent URL (/authorize?resource=…, bound-B / bound-C).
	// Optional — when nil (or it resolves empty) the handler logs a warn
	// and emits consent_required without a consent_url (omitted via
	// omitempty). Operators who want re-consent redirects must wire this;
	// the OSS default adapter (cmd/authserver/serve.go) does so.
	IssuerProvider output.IssuerProvider
}

// RegisterRoutes registers all OAuth routes on the mux.
func RegisterRoutes(mux *http.ServeMux, deps Deps, sessMW *shared.SessionMiddleware, obs *observability.Provider) {
	// DCR endpoint.
	if deps.DCR != nil {
		rh := &registerHandler{dcr: deps.DCR, obs: obs}
		mux.HandleFunc("POST /oauth/register", rh.handleRegister)
	}

	// Authorization + token endpoints.
	if deps.Authorize != nil || deps.Token != nil || deps.ClientCredentials != nil || deps.TokenExchange != nil || deps.JWTBearer != nil {
		oh := &oauthHandler{
			authorize:      deps.Authorize,
			token:          deps.Token,
			clientCreds:    deps.ClientCredentials,
			tokenExchange:  deps.TokenExchange,
			jwtBearer:      deps.JWTBearer,
			session:        sessMW,
			obs:            obs,
			urls:           deps.URLs,
			issuerProvider: deps.IssuerProvider,
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

	// Introspection endpoint (RFC 7662). The route is registered whenever a
	// provider exists; deps.OAuthConfig gates it per request (404 when
	// IntrospectionEnabled is false), keeping discovery and the endpoint in sync.
	if deps.Introspect != nil {
		ih := &introspectHandler{introspect: deps.Introspect, oauthConfig: deps.OAuthConfig, obs: obs}
		mux.HandleFunc("POST /oauth/introspect", ih.handleIntrospect)
	}
}

// LoginDeps holds the dependencies for login/logout handlers.
type LoginDeps struct {
	Auth    UserAuthProvider
	Display output.LoginDisplayProvider // supplies DisplayName + ShowLocalLogin per request
	URLs    output.URLBuilder           // builds absolute URLs for login/logout responses
	// Audit records the lockout event. Optional: nil disables recording, which
	// is the right default for tests and never affects the lockout itself.
	Audit AuditRecorder
}

// RegisterLoginRoutes registers login/logout routes on the mux.
//
// LoginDeps.Display MUST be non-nil — there is no silent fallback. Callers
// must supply one explicitly (use internal/adapters/static.NewLoginDisplayProvider
// with config.OIDCConfig{ShowLocalLogin: true} for the default — the zero
// value of OIDCConfig disables local login). A nil provider panics at
// registration time rather than nil-deref'ing the first request.
func RegisterLoginRoutes(mux *http.ServeMux, deps LoginDeps, sessMW *shared.SessionMiddleware, lockout *shared.AuthLockout, obs *observability.Provider) {
	if deps.Auth == nil {
		return
	}
	if deps.Display == nil {
		panic("oauth.RegisterLoginRoutes: LoginDeps.Display is required (use internal/adapters/static.NewLoginDisplayProvider(config.OIDCConfig{ShowLocalLogin: true}) for the default, or pass your own implementation)")
	}
	if deps.URLs == nil {
		panic("oauth.RegisterLoginRoutes: LoginDeps.URLs (URLBuilder) is required (use internal/adapters/static.NewURLBuilder() for the default, or pass your own implementation)")
	}

	lh := &loginHandler{
		auth:    deps.Auth,
		session: sessMW,
		obs:     obs,
		lockout: lockout,
		display: deps.Display,
		urls:    deps.URLs,
		audit:   deps.Audit,
	}
	mux.HandleFunc("GET /login", lh.handleGetLogin)
	mux.HandleFunc("POST /login", lh.handlePostLogin)
	mux.HandleFunc("POST /logout", lh.handlePostLogout)
}

// ConsentDeps holds the dependencies for consent handlers.
type ConsentDeps struct {
	Consent ConsentProvider
	URLs    output.URLBuilder
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
		urls:    deps.URLs,
	}
	mux.Handle("GET /consent", sessMW.Wrap(http.HandlerFunc(ch.handleGetConsent)))
	mux.Handle("POST /consent", sessMW.Wrap(http.HandlerFunc(ch.handlePostConsent)))
}

// OIDCDeps holds the dependencies for OIDC handlers.
type OIDCDeps struct {
	OIDC       OIDCFlowProvider
	URLs       output.URLBuilder              // builds absolute URLs for OIDC redirects
	StateCodec output.StateCodec              // required when OIDC != nil
	StateCfg   output.OIDCStateConfigProvider // required when OIDC != nil
}

// RegisterOIDCRoutes registers OIDC upstream federation routes on the mux.
//
// URLs and StateCodec must be non-nil when deps.OIDC is non-nil; both panic
// at registration time otherwise.
func RegisterOIDCRoutes(mux *http.ServeMux, deps OIDCDeps, sessMW *shared.SessionMiddleware, obs *observability.Provider) {
	if deps.OIDC == nil {
		return
	}
	if deps.URLs == nil {
		panic("oauth.RegisterOIDCRoutes: OIDCDeps.URLs (URLBuilder) is required (use internal/adapters/static.NewURLBuilder() for the default, or pass your own implementation)")
	}
	if deps.StateCodec == nil {
		panic("RegisterOIDCRoutes: StateCodec is nil; construct one with static.NewStateCodec(static.NewStateCodecConfigProvider(key)) or substitute via OIDCDeps.StateCodec")
	}
	if deps.StateCfg == nil {
		panic("RegisterOIDCRoutes: StateCfg is nil; construct one with static.NewOIDCStateConfigProvider(...) or substitute via OIDCDeps.StateCfg")
	}

	oh := &oidcHandler{
		oidc:     deps.OIDC,
		session:  sessMW,
		obs:      obs,
		codec:    deps.StateCodec,
		urls:     deps.URLs,
		stateCfg: deps.StateCfg,
	}
	mux.HandleFunc("GET /oidc/start", oh.handleOIDCStart)
	mux.HandleFunc("GET /oidc/callback", oh.handleOIDCCallback)
}
