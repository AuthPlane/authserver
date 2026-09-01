// Package public provides the public-facing HTTP server, assembling routes
// from the oauth, vault, and wellknown sub-packages.
package public

import (
	"context"
	"net"
	"net/http"

	connectionapi "github.com/authplane/authserver/api/public/connection"
	"github.com/authplane/authserver/api/public/oauth"
	"github.com/authplane/authserver/api/public/wellknown"
	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// Server is the public-facing HTTP server.
type Server struct {
	srv *http.Server
	obs *observability.Provider
}

// SessionCookie carries the boot-time session-cookie attributes the server
// reads directly: the cookie Name (default "authserver_session" when empty) and
// the deployment's Secure/HTTPS posture (drives HSTS and the Secure floor that
// an alternative SessionConfigProvider may only tighten above, never downgrade).
type SessionCookie struct {
	Name   string
	Secure bool
}

// Deps holds the dependencies injected into the public HTTP server.
type Deps struct {
	JWKS wellknown.JWKSProvider
	// ASMetadata assembles the AS discovery document (RFC 8414). Required for
	// the oauth-authorization-server / openid-configuration routes; built in
	// cmd from the static providers (api/ may not import services/adapters).
	ASMetadata        input.ASMetadataPort
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
	// OAuthConfig gates POST /oauth/introspect at runtime (IntrospectionEnabled)
	// from the same source as the discovery document. Optional.
	OAuthConfig output.OAuthConfigProvider
	Health      wellknown.HealthChecker
	OIDC        oauth.OIDCFlowProvider
	// LoginDisplay supplies the login page's presentation fields (OIDC
	// button label + show-local-login) per request. It is required when the
	// login routes are registered: RegisterLoginRoutes panics if it is nil —
	// there is no silent fallback. It carries only presentation data, never
	// the upstream client secret.
	LoginDisplay output.LoginDisplayProvider
	// URLs constructs URLs for internal authserver routes (the OIDC start
	// link, the post-login redirect destination) and resolves the mount path
	// prefix + cookie scope (PathPrefix, CookiePath). REQUIRED: NewServer
	// panics if nil — there is no silent fallback. The OSS default,
	// static.NewURLBuilder(), serves at the root (empty prefix, "/" cookie
	// path, byte-identical to the pre-port behavior); an alternative builder
	// may scope URLs/cookies under a mount path.
	URLs output.URLBuilder
	// StateCodec encodes/decodes the OAuth state parameter for the OIDC
	// federation flow. Required when OIDC is non-nil; nil panics at
	// route registration time. Default impl: static.NewStateCodec.
	StateCodec output.StateCodec
	// SessionSecretProvider supplies the HMAC secret for session cookies / CSRF
	// tokens per request. REQUIRED: NewServer panics if it is nil — there is no
	// silent fallback. cmd/authserver/serve.go wires the OSS default
	// static.NewSessionSecretProvider over the secret it resolves from
	// cfg.Session.Secret (or a random ephemeral secret when that is unset). An
	// alternative provider can source the secret per deployment (KMS / HSM /
	// env-keyed rotation).
	SessionSecretProvider output.SessionSecretProvider
	// SessionConfigProvider supplies the session-cookie policy
	// (MaxAge/Secure/SameSite/FailClosed) per request. REQUIRED: NewServer
	// panics if nil. cmd/authserver/serve.go wires the OSS default
	// static.NewSessionConfigProvider over cfg.Session, byte-identical to the
	// pre-seam server. An alternative provider may resolve policy per request.
	SessionConfigProvider output.SessionConfigProvider
	// OIDCStateConfigProvider resolves the OIDC state-cookie TTL per request.
	// REQUIRED when OIDC routes register. Default: static.NewOIDCStateConfigProvider.
	OIDCStateConfigProvider output.OIDCStateConfigProvider
	// SessionCookie carries the only two boot-time session-cookie attributes the
	// server reads directly. The cookie *policy* (MaxAge/SameSite/FailClosed)
	// comes from SessionConfigProvider and the signing secret from
	// SessionSecretProvider — neither is settable here, so a misconfiguration
	// can't hide in an ignored field.
	SessionCookie SessionCookie
	RateLimitCfg  config.RateLimitConfig
	Connect       connectionapi.ConnectProvider
	// IssuerProvider resolves the AS issuer URL — the public base for
	// everything under the host. The OAuth sub-package builds both
	// consent_required URL flavors from it: the broker upstream re-connect
	// URL (/connect/<provider>) and the AS-side re-consent URL
	// (/authorize?resource=…, token-exchange and bound-B/bound-C flows).
	// In the OSS deployment this is the static cfg.Server.Issuer.
	IssuerProvider output.IssuerProvider

	// CORSConfigProvider resolves the CORS allowed-origins allowlist per
	// request for the browser-facing endpoints (token, introspection,
	// revocation, registration, discovery). REQUIRED: NewServer panics if it is
	// nil — there is no silent fallback. cmd/authserver/serve.go wires the OSS
	// default static.NewCORSConfigProvider(cfg.Server.AllowedOrigins), which
	// returns the boot allowlist on every call (byte-identical to the pre-seam
	// server). A resolution failure fails closed: no CORS headers for that
	// request, never a fallback to a stale or process-wide list. An alternative
	// provider may source the allowlist per request.
	CORSConfigProvider output.CORSConfigProvider

	// BuildChain composes the middleware chain around the routed handler. Nil —
	// the default — builds DefaultChain, byte-for-byte the chain this server has
	// always served. A distribution supplies a builder to insert middleware
	// inside the chain, and is expected to compose around DefaultChain rather
	// than restate it (see ChainBuilder).
	//
	// The builder supplies handlers; it does not own the order. SecurityHeaders
	// and Recover wrap everything DefaultChain composes, including anything the
	// builder injects.
	BuildChain ChainBuilder

	// DPoP (RFC 9449) — optional.
	DPoPNonce oauth.DPoPNonceIssuer // non-nil when DPoP is enabled
	DPoPCfg   config.DPoPConfig     // DPoP configuration

	// Users is consulted by SessionMiddleware to reject session cookies naming a
	// user who no longer exists OR is no longer active. Pass the same UserStore
	// the rest of the app uses — production wraps it in storage.WithUserCache
	// so this lookup does not become a DB query per request. When nil, the
	// middleware accepts any cookie that passes HMAC + expiry validation. Some
	// tests rely on that; production must not, since /authorize and /consent
	// have no user check of their own, so this is what makes a disable take
	// effect on the front channel. See SessionMiddleware.SetUserStore.
	Users output.UserStore

	// Audit records the auth-failure lockout event. Optional: nil disables
	// recording and changes nothing about the lockout itself.
	Audit oauth.AuditRecorder
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

	// Session middleware. The HMAC secret provider is REQUIRED — there is no
	// silent fallback. A missing provider must fail loudly at startup rather
	// than sign sessions with a random ephemeral secret that silently breaks
	// on restart. The cmd wiring injects the OSS default: serve.go resolves the
	// secret from cfg.Session.Secret (or a random ephemeral one when unset) and
	// wraps it in static.NewSessionSecretProvider; an alternative provider can be
	// substituted for a per-deployment source.
	if deps.SessionSecretProvider == nil {
		panic("public.NewServer: Deps.SessionSecretProvider (output.SessionSecretProvider) is required")
	}
	if deps.SessionConfigProvider == nil {
		panic("public.NewServer: Deps.SessionConfigProvider (output.SessionConfigProvider) is required")
	}
	cookieName := deps.SessionCookie.Name
	if cookieName == "" {
		cookieName = "authserver_session"
	}
	// The boot Secure floor is the deployment's HTTPS posture (same source as
	// isSecure/HSTS below): an alternative SessionConfigProvider may only tighten
	// Secure above it, never downgrade an HTTPS/HSTS deployment to non-Secure
	// cookies. Passed at construction so the floor can't be silently forgotten.
	sessMW := shared.NewSessionMiddleware(
		deps.SessionSecretProvider,
		deps.SessionConfigProvider,
		cookieName,
		deps.SessionCookie.Secure,
	)
	if deps.Users != nil {
		sessMW.SetUserStore(deps.Users)
	}
	sessMW.SetLogger(obs.Logger)

	// Rate limiting and auth-failure lockout are separate controls with
	// separate scopes. Throughput wraps every public route; the lockout is
	// handed to the login routes alone, so no discovery, JWKS or token request
	// can ever be rejected because someone else mistyped a password.
	// The lockout is built unconditionally, outside the throughput flag. They
	// are separate controls and they need separate switches: rate_limit.enabled
	// reads as "throughput limiting", and the threat model tells operators to
	// disable it in favor of an external limiter on multi-instance deployments.
	// A gateway rate limiter counts requests per address — it cannot count failed
	// logins per account, so following that advice used to switch off a control
	// nothing replaced, silently. AuthLockout's own switch is AuthFailMax <= 0,
	// which every one of its methods already honors.
	var inner http.Handler = mux
	if deps.RateLimitCfg.Enabled {
		inner = shared.NewRateLimiter(ctx, deps.RateLimitCfg).Middleware(mux)
	}
	lockout := shared.NewAuthLockout(ctx, deps.RateLimitCfg, obs.Logger)

	// Login display is required: RegisterLoginRoutes panics if it is nil
	// when login routes are registered. Callers must supply one explicitly,
	// e.g. static.NewLoginDisplayProvider(cfg.OIDC).
	loginDisplay := deps.LoginDisplay

	// URL builder is required — there is no silent fallback. A root
	// deployment passes static.NewURLBuilder(): empty mount prefix and
	// "/" cookie path, byte-identical to the pre-port hardcoded behavior.
	if deps.URLs == nil {
		panic("public.NewServer: Deps.URLs (output.URLBuilder) is required")
	}
	urls := deps.URLs

	// CORS allowed-origins provider is required — there is no silent fallback.
	// The allowlist is resolved per request; a resolution failure fails closed
	// (no CORS headers). The cmd wiring injects the OSS default,
	// static.NewCORSConfigProvider(cfg.Server.AllowedOrigins), which returns the
	// boot allowlist on every call — byte-identical to the pre-seam server. An
	// alternative provider may vary origin policy per request.
	if deps.CORSConfigProvider == nil {
		panic("public.NewServer: Deps.CORSConfigProvider (output.CORSConfigProvider) is required")
	}
	// CORS middleware sits before rate limiting so preflight isn't throttled
	// (see the middleware chain below).
	corsMW := shared.CORSMiddleware(deps.CORSConfigProvider, obs.Logger)

	// Scope the session cookie's Path to the AS mount (via urls.CookiePath).
	// At the root this is "/", byte-identical to the pre-patch behavior.
	sessMW.SetURLBuilder(urls)

	// Determine if HTTPS is enforced (for HSTS header).
	isSecure := deps.SessionCookie.Secure

	// The middleware chain. Its composition and order live in DefaultChain
	// (chain.go), which owns them; restating the order here would be a second
	// copy free to drift from the first — the very thing this seam exists to
	// prevent. deps.BuildChain lets a distribution compose around DefaultChain,
	// inserting middleware INSIDE the chain, so a response that middleware writes
	// still carries CORS and security headers and is recovered/traced/metered/
	// logged. Nil builds the default chain: the OSS server composes exactly as it
	// did before the seam existed.
	build := deps.BuildChain
	if build == nil {
		build = DefaultChain
	}
	s.srv.Handler = build(ChainDeps{Obs: obs, Secure: isSecure, CORS: corsMW}, inner)

	// Register wellknown/infrastructure routes (JWKS, AS metadata, health).
	wellknown.RegisterRoutes(mux, wellknown.Deps{
		JWKS:       deps.JWKS,
		ASMetadata: deps.ASMetadata,
		Health:     deps.Health,
	}, obs)

	// Register OAuth routes (authorize, token, register, revoke, introspect).
	oauthDeps := oauth.Deps{
		URLs:              urls,
		Authorize:         deps.Authorize,
		Token:             deps.Token,
		ClientCredentials: deps.ClientCredentials,
		TokenExchange:     deps.TokenExchange,
		JWTBearer:         deps.JWTBearer,
		Revoke:            deps.Revoke,
		DCR:               deps.DCR,
		Introspect:        deps.Introspect,
		OAuthConfig:       deps.OAuthConfig,
		IssuerProvider:    deps.IssuerProvider,
	}
	if deps.DPoPNonce != nil {
		oauthDeps.DPoPNonce = deps.DPoPNonce
		oauthDeps.DPoPNonceTTL = deps.DPoPCfg.NonceTTL
	}
	oauth.RegisterRoutes(mux, oauthDeps, sessMW, obs)

	// Register login/logout routes.
	oauth.RegisterLoginRoutes(mux, oauth.LoginDeps{
		Auth:    deps.Auth,
		Display: loginDisplay,
		URLs:    urls,
		Audit:   deps.Audit,
	}, sessMW, lockout, obs)

	// Register consent routes.
	oauth.RegisterConsentRoutes(mux, oauth.ConsentDeps{
		Consent: deps.Consent,
		URLs:    urls,
	}, sessMW, obs)

	// Register OIDC upstream federation routes.
	oauth.RegisterOIDCRoutes(mux, oauth.OIDCDeps{
		OIDC:       deps.OIDC,
		URLs:       urls,
		StateCodec: deps.StateCodec,
		StateCfg:   deps.OIDCStateConfigProvider,
	}, sessMW, obs)

	// Register Broker routes (connect/callback/list/delete only —
	// token vending flows through POST /oauth/token with resource=<service>).
	connectionapi.RegisterRoutes(mux, connectionapi.Deps{Connect: deps.Connect, URLs: urls}, sessMW, obs)

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
