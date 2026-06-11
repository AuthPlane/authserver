//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/crypto"
)

// MCPResourceServer is a minimal MCP resource server for E2E tests.
// It serves PRM, validates JWTs, and has 2 test tool endpoints.
type MCPResourceServer struct {
	Server     *httptest.Server
	URI        string   // The resource URI (server URL)
	JWKSURL    string   // URL to fetch JWKS from authserver
	AuthServer string   // authserver issuer URL
	Scopes     []string // scopes this server supports
}

// NewMCPResourceServer creates and starts a minimal MCP resource server.
// The AuthServer/JWKSURL fields can be updated after creation for two-phase setup.
func NewMCPResourceServer(t *testing.T, scopes []string) *MCPResourceServer {
	t.Helper()

	rs := &MCPResourceServer{
		Scopes: scopes,
	}

	mux := http.NewServeMux()

	// PRM endpoint — reads from rs fields at request time (not closure capture).
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		prm := map[string]any{
			"resource":                 rs.URI,
			"authorization_servers":    []string{rs.AuthServer},
			"scopes_supported":         rs.Scopes,
			"bearer_methods_supported": []string{"header"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(prm)
	})

	// Tool: echo — returns the request body.
	mux.HandleFunc("POST /tools/echo", func(w http.ResponseWriter, r *http.Request) {
		claims, err := rs.validateJWT(r)
		if err != nil {
			rs.writeUnauthorized(w, err)
			return
		}
		if !scopeContains(claims.Scope, "tools/echo") {
			rs.writeForbidden(w, "insufficient scope")
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"result":    string(body),
			"client_id": claims.ClientID,
			"user_id":   claims.Subject,
		})
	})

	// Tool: db_query — returns a fixed result.
	mux.HandleFunc("POST /tools/db_query", func(w http.ResponseWriter, r *http.Request) {
		claims, err := rs.validateJWT(r)
		if err != nil {
			rs.writeUnauthorized(w, err)
			return
		}
		if !scopeContains(claims.Scope, "tools/db_query") {
			rs.writeForbidden(w, "insufficient scope")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"rows": []map[string]any{
				{"id": 1, "name": "test"},
			},
		})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	rs.Server = server
	rs.URI = server.URL

	return rs
}

// SetAuthServer updates the auth server URL (for two-phase setup).
func (rs *MCPResourceServer) SetAuthServer(issuer string) {
	rs.AuthServer = issuer
	rs.JWKSURL = issuer + "/.well-known/jwks.json"
}

// validateJWT extracts and validates the Bearer token from the request.
func (rs *MCPResourceServer) validateJWT(r *http.Request) (*crypto.AccessTokenClaims, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		return nil, fmt.Errorf("missing Bearer token")
	}
	tokenStr := auth[7:]

	// Fetch JWKS from authserver.
	jwks, err := rs.fetchJWKS()
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}

	// Verify token.
	claims, err := crypto.VerifyAccessToken(tokenStr, jwks)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// Check audience matches this resource server.
	if !audienceContains(claims.Audience, rs.URI) {
		return nil, fmt.Errorf("audience mismatch: expected %s, got %v", rs.URI, claims.Audience)
	}

	return claims, nil
}

func (rs *MCPResourceServer) fetchJWKS() (*jose.JSONWebKeySet, error) {
	resp, err := http.Get(rs.JWKSURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}
	return &jwks, nil
}

func (rs *MCPResourceServer) writeUnauthorized(w http.ResponseWriter, err error) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="invalid_token", error_description="%s"`, err.Error()))
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func (rs *MCPResourceServer) writeForbidden(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_scope", error_description="%s"`, msg))
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func scopeContains(scopeStr, target string) bool {
	for _, s := range strings.Fields(scopeStr) {
		if s == target {
			return true
		}
	}
	return false
}

func audienceContains(aud []string, target string) bool {
	for _, a := range aud {
		if a == target {
			return true
		}
	}
	return false
}
