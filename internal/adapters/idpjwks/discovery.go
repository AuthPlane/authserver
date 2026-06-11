package idpjwks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// oidcConfiguration represents the subset of OpenID Connect discovery metadata we need.
type oidcConfiguration struct {
	Issuer  string `json:"issuer"`
	JWKSUri string `json:"jwks_uri"`
}

// DiscoverJWKSUri fetches the OIDC discovery document from the issuer's
// /.well-known/openid-configuration and returns the jwks_uri.
func DiscoverJWKSUri(ctx context.Context, issuerURL string) (string, error) {
	client := ssrfSafeClient(10_000_000_000) // 10s

	wellKnown := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("create discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch discovery document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024)) // 256KB limit
	if err != nil {
		return "", fmt.Errorf("read discovery response: %w", err)
	}

	var cfg oidcConfiguration
	if err := json.Unmarshal(body, &cfg); err != nil {
		return "", fmt.Errorf("parse discovery document: %w", err)
	}

	if cfg.JWKSUri == "" {
		return "", fmt.Errorf("discovery document missing jwks_uri")
	}

	return cfg.JWKSUri, nil
}
