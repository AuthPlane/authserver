package oidc

import (
	"context"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"github.com/authplane/authserver/internal/ports/output"
)

// idTokenClaims holds the claims we verify from the upstream ID token.
type idTokenClaims struct {
	Issuer   string               `json:"iss"`
	Subject  string               `json:"sub"`
	Audience josejwt.Audience     `json:"aud"`
	Expiry   *josejwt.NumericDate `json:"exp"`
	Nonce    string               `json:"nonce"`
	Email    string               `json:"email"`
	Name     string               `json:"name"`
	Groups   []string             `json:"groups"`
}

func (p *Provider) verifyIDToken(ctx context.Context, cfg output.OIDCConfig, doc DiscoveryDoc, jwks *jose.JSONWebKeySet, rawToken, expectedNonce string) (*output.OIDCTokenResult, error) {
	ctx, span := p.tracer.Start(ctx, "OIDC.verifyIDToken")
	defer span.End()

	tok, err := josejwt.ParseSigned(rawToken, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
	})
	if err != nil {
		return nil, fmt.Errorf("parse ID token: %w", err)
	}

	headers := tok.Headers
	if len(headers) == 0 {
		return nil, fmt.Errorf("ID token has no headers")
	}
	kid := headers[0].KeyID

	keys := getKeys(jwks, kid)
	if len(keys) == 0 {
		// kid miss — the signing key likely rotated. Force a fresh fetch that
		// bypasses the cache (configured bytes stay authoritative and cannot be
		// refreshed). The cache hit/miss counters live in resolveJWKS, where
		// they reflect whether we went to the network.
		p.logger.DebugContext(ctx, "JWKS kid miss, refreshing", "kid", kid)
		refreshed, ferr := p.refreshJWKS(ctx, cfg, doc)
		if ferr != nil {
			return nil, fmt.Errorf("JWKS refresh: %w", ferr)
		}
		keys = getKeys(refreshed, kid)
		if len(keys) == 0 {
			return nil, fmt.Errorf("no matching key for kid %q", kid)
		}
	}

	var claims idTokenClaims
	if err := tok.Claims(keys[0].Key, &claims); err != nil {
		return nil, fmt.Errorf("verify ID token signature: %w", err)
	}

	if claims.Issuer != cfg.Issuer {
		return nil, fmt.Errorf("ID token issuer %q does not match expected %q", claims.Issuer, cfg.Issuer)
	}
	if !claims.Audience.Contains(cfg.ClientID) {
		return nil, fmt.Errorf("ID token audience does not contain client_id %q", cfg.ClientID)
	}
	if claims.Expiry == nil || claims.Expiry.Time().Before(time.Now()) {
		return nil, fmt.Errorf("ID token is expired")
	}
	if claims.Nonce != expectedNonce {
		return nil, fmt.Errorf("ID token nonce mismatch")
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("ID token missing sub claim")
	}

	return &output.OIDCTokenResult{
		Subject: claims.Subject,
		Email:   claims.Email,
		Name:    claims.Name,
		Issuer:  claims.Issuer,
		Groups:  claims.Groups,
	}, nil
}

func getKeys(jwks *jose.JSONWebKeySet, kid string) []jose.JSONWebKey {
	if jwks == nil {
		return nil
	}
	if kid == "" {
		return jwks.Keys
	}
	return jwks.Key(kid)
}
