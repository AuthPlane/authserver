package connectionapi

import (
	"context"
	"net/http"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

// ConnectionMeta is re-exported from internal/ports/input so handlers
// serialize the canonical input-layer DTO without taking a direct dependency
// on internal/services.
type ConnectionMeta = input.ConnectionMeta

// CompleteConnectResult bundles the metadata the callback handler needs to
// render the post-connect redirect.
type CompleteConnectResult = input.CompleteConnectResult

// ConnectProvider is the service-layer surface the connection handlers depend
// on. : the path-parameter is the BrokerProvider slug, not the resource
// slug; resourceSlug is an optional originating-resource hint that gates the
// per-resource policy.connect.allowed_return_urls lookup.
type ConnectProvider interface {
	StartConnect(ctx context.Context, userID, providerSlug, resourceSlug, returnURL string) (string, error)
	CompleteConnect(ctx context.Context, userID, stateToken, code string) (CompleteConnectResult, error)
	Disconnect(ctx context.Context, userID, providerSlug string) error
	ListConnections(ctx context.Context, userID string) ([]ConnectionMeta, error)
}

// Deps holds the dependencies for the public connection handlers.
type Deps struct {
	Connect ConnectProvider
}

// RegisterRoutes wires the user-facing /connect + /connections routes.
// Token vending flows through POST /oauth/token with resource=<slug>; this
// package only serves the connect/disconnect + connections-listing surface.
//
// when deps.Connect is nil (operator opted out — boot's feature
// self-check would have failed if the config were merely partial), the
// routes are still registered but return a typed feature_disabled error.
// The pre- behavior was to leave the routes unbound, which produced
// a 404 with no diagnostic — the canonical empty-consent_url failure mode.
func RegisterRoutes(mux *http.ServeMux, deps Deps, sessMW *shared.SessionMiddleware, obs *observability.Provider) {
	if deps.Connect == nil {
		registerDisabledStubs(mux, sessMW)
		return
	}

	vh := &handler{
		connect: deps.Connect,
		session: sessMW,
		obs:     obs,
	}
	mux.Handle("GET /connect/{provider}", sessMW.Wrap(http.HandlerFunc(vh.handleConnect)))
	mux.Handle("GET /connect/{provider}/callback", sessMW.Wrap(http.HandlerFunc(vh.handleCallback)))
	mux.Handle("GET /connections", sessMW.Wrap(http.HandlerFunc(vh.handleListConnections)))
	mux.Handle("DELETE /connections/{provider}", sessMW.Wrap(http.HandlerFunc(vh.handleDeleteConnection)))
}

// registerDisabledStubs binds the /connect + /connections paths to a
// handler that returns 503 service_unavailable naming connect.state_secret
// as the config key to set. This replaces the legacy 404 that left
// operators staring at empty consent_url responses with no log line.
func registerDisabledStubs(mux *http.ServeMux, sessMW *shared.SessionMiddleware) {
	stub := http.HandlerFunc(featureDisabledStub)
	mux.Handle("GET /connect/{provider}", sessMW.Wrap(stub))
	mux.Handle("GET /connect/{provider}/callback", sessMW.Wrap(stub))
	mux.Handle("GET /connections", sessMW.Wrap(stub))
	mux.Handle("DELETE /connections/{provider}", sessMW.Wrap(stub))
}

func featureDisabledStub(w http.ResponseWriter, _ *http.Request) {
	err := domain.NewFeatureDisabledError("connect", "connect.state_secret")
	shared.WriteOAuthError(w, http.StatusServiceUnavailable, err.Code(), err.Error())
}
