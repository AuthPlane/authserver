// Package public provides the public-facing HTTP server, assembling routes
// from the oauth, vault, and wellknown sub-packages.
package public

import (
	"context"
	"crypto/rand"
	"net"
	"net/http"
	"time"

	connectionapi "github.com/authplane/authserver/api/public/connection"
	"github.com/authplane/authserver/api/public/oauth"
	"github.com/authplane/authserver/api/public/wellknown"
	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// Server is the public-facing HTTP server.
type Server struct {
	srv *http.Server
	obs *observability.Provider
}

// Deps holds the dependencies injected into the public HTTP server.
type Deps struct {
	JWKS              wellknown.JWKSProvider
	DCR               oauth.DCRProvider
	Auth              oauth.UserAuthProvider
	Authorize         oauth.AuthorizeProvider
	Consent           oauth.ConsentProvider
	Token             oauth.TokenProvider
	ClientCredentials oauth.ClientCredentialsProvider
	TokenExchange     oauth.TokenExchangeProvider
	JWTBearer         oauth.JWTBearerProvider
	Revoke            oauth.RevocationProvider
	Introspect        oauth.IntrospectionProvider
	Health            wellknown.HealthChecker
	OIDC              oauth.OIDCFlowProvider
	OIDCConfig        config.OIDCConfig
	ResourceServers   wellknown.ResourceListerFunc
	SessionCfg        config.SessionConfig
	RateLimitCfg      config.RateLimitConfig
	Connect           connectionapi.ConnectProvider
	// ConnectConsentBaseURL is the base URL used to build /connect/<provider>
	// consent_url values in consent_required responses from the token
	// endpoint (Broker upstream re-connect path). Populated from
	// cfg.Connect.RedirectBaseURL.
	ConnectConsentBaseURL string
	// AuthorizeBaseURL is the AS issuer URL used to build
	// /authorize?resource=<slug> consent_url values for AS-side re-consent
	// flows (bound-B / bound-C, ). Populated from cfg.Server.Issuer.
	AuthorizeBaseURL string

	// DPoP (RFC 9449) — optional.
	DPoPNonce oauth.DPoPNonceIssuer // non-nil when DPoP is enabled
	DPoPCfg   config.DPoPConfig     // DPoP configuration

	// CIMD (Client ID Metadata Document) — optional.
	HasCIMD bool

	// Agent identity (Authplane extension) — optional.
	HasAgentIdentity bool

	// Users is consulted by SessionMiddleware to reject session cookies whose
	// userID no longer exists in the database. Pass the same UserStore
	// the rest of the app uses — production wraps it in storage.WithUserCache
	// so this lookup does not become a DB query per request. When nil, the
	// middleware accepts any cookie that passes HMAC + expiry validation —
	// the right default for tests, but not for production where a stale cookie
	// can survive a `docker compose down -v` and trip an FK constraint
	// downstream (e.g., broker_grants.user_id).
	Users output.UserStore
}

// NewServer creates the public HTTP server with routes wired.
func NewServer(ctx context.Context, cfg config.ServerConfig, deps Deps, obs *observability.Provider) *Server {
	mux := http.NewServeMux()

	s := &Server{
		srv: &http.Server{
			Addr:         cfg.Address,
			Handler:      mux,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  cfg.IdleTimeout,
		},
		obs: obs,
	}

	// Session middleware.
	secret := []byte(deps.SessionCfg.Secret)
	if len(secret) == 0 {
		obs.Logger.Warn("session.secret not configured - using random ephemeral secret (sessions will not survive restarts)")
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			panic("crypto/rand: " + err.Error())
		}
	}
	sessMW := shared.NewSessionMiddleware(
		secret,
		deps.SessionCfg.CookieName,
		deps.SessionCfg.MaxAge,
		deps.SessionCfg.Secure,
		shared.ParseSameSite(deps.SessionCfg.SameSite),
	)
	if deps.SessionCfg.CookieName == "" {
		sessMW.CookieName = "authserver_session"
	}
	if deps.SessionCfg.MaxAge == 0 {
		sessMW.MaxAge = 24 * time.Hour
	}
	if deps.Users != nil {
		sessMW.SetUserStore(deps.Users)
	}
	sessMW.SetLogger(obs.Logger)
	sessMW.SetFailClosed(deps.SessionCfg.FailClosed)

	// Rate limiting middleware.
	var rl *shared.RateLimiter
	var inner http.Handler = mux
	if deps.RateLimitCfg.Enabled {
		rl = shared.NewRateLimiter(ctx, deps.RateLimitCfg)
		inner = rl.Middleware(mux)
	}

	// CORS middleware (before rate limiting so preflight isn't throttled).
	corsMW := shared.CORSMiddleware(shared.CORSConfig{AllowedOrigins: cfg.AllowedOrigins})

	// Determine if HTTPS is enforced (for HSTS header).
	isSecure := deps.SessionCfg.Secure

	// Observability middleware chain:
	// SecurityHeaders -> Recover -> RequestID -> CORS -> Tracing -> Metrics -> Logging -> inner
	obsMW := observability.NewHTTPMiddleware(obs)
	s.srv.Handler = shared.SecurityHeaders(isSecure)(
		obsMW.Recover()(
			obsMW.RequestID()(
				corsMW(
					obsMW.Tracing()(
						obsMW.Metrics()(
							obsMW.Logging()(inner),
						),
					),
				),
			),
		),
	)

	// Register wellknown/infrastructure routes (JWKS, AS metadata, PRM, health).
	wellknown.RegisterRoutes(mux, wellknown.Deps{
		JWKS:                 deps.JWKS,
		ServerCfg:            cfg,
		ResourceServers:      deps.ResourceServers,
		Health:               deps.Health,
		HasIntrospection:     deps.Introspect != nil,
		HasClientCredentials: deps.ClientCredentials != nil,
		HasTokenExchange:     deps.TokenExchange != nil,
		HasDPoP:              deps.DPoPCfg.Enabled,
		HasAgentIdentity:     deps.HasAgentIdentity,
		HasCIMD:              deps.DCR != nil,
		HasJWTBearer:         deps.JWTBearer != nil,
	}, obs)

	// Register OAuth routes (authorize, token, register, revoke, introspect).
	oauthDeps := oauth.Deps{
		Authorize:             deps.Authorize,
		Token:                 deps.Token,
		ClientCredentials:     deps.ClientCredentials,
		TokenExchange:         deps.TokenExchange,
		JWTBearer:             deps.JWTBearer,
		Revoke:                deps.Revoke,
		DCR:                   deps.DCR,
		Introspect:            deps.Introspect,
		ConnectConsentBaseURL: deps.ConnectConsentBaseURL,
		AuthorizeBaseURL:      deps.AuthorizeBaseURL,
	}
	if deps.DPoPNonce != nil {
		oauthDeps.DPoPNonce = deps.DPoPNonce
		oauthDeps.DPoPNonceTTL = deps.DPoPCfg.NonceTTL
	}
	oauth.RegisterRoutes(mux, oauthDeps, sessMW, rl, obs)

	// Register login/logout routes.
	oauth.RegisterLoginRoutes(mux, oauth.LoginDeps{
		Auth:            deps.Auth,
		OIDCDisplayName: deps.OIDCConfig.DisplayName,
		ShowLocalLogin:  deps.OIDCConfig.ShowLocalLogin,
	}, sessMW, rl, obs)

	// Register consent routes.
	oauth.RegisterConsentRoutes(mux, oauth.ConsentDeps{
		Consent: deps.Consent,
	}, sessMW, obs)

	// Register OIDC upstream federation routes.
	oauth.RegisterOIDCRoutes(mux, oauth.OIDCDeps{
		OIDC:        deps.OIDC,
		RedirectURI: deps.OIDCConfig.RedirectURI,
	}, sessMW, obs)

	// Register Broker routes (connect/callback/list/delete only —
	// token vending flows through POST /oauth/token with resource=<service>).
	connectionapi.RegisterRoutes(mux, connectionapi.Deps{Connect: deps.Connect}, sessMW, obs)

	return s
}

// Handler returns the server's HTTP handler for testing.
func (s *Server) Handler() http.Handler {
	return s.srv.Handler
}

// Start begins listening. It blocks until the server stops.
func (s *Server) Start() error {
	s.obs.Logger.Info("http server listening", "addr", s.srv.Addr)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", s.srv.Addr)
	if err != nil {
		return err
	}
	return s.srv.Serve(ln)
}

// Shutdown gracefully drains in-flight requests.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}
