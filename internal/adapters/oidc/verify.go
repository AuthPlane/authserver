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

func (p *Provider) verifyIDToken(ctx context.Context, rawToken, expectedNonce string) (*output.OIDCTokenResult, error) {
	ctx, span := p.tracer.Start(ctx, "OIDC.verifyIDToken")
	defer span.End()

	// Parse the JWT.
	tok, err := josejwt.ParseSigned(rawToken, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
	})
	if err != nil {
		return nil, fmt.Errorf("parse ID token: %w", err)
	}

	// Find the signing key.
	headers := tok.Headers
	if len(headers) == 0 {
		return nil, fmt.Errorf("ID token has no headers")
	}
	kid := headers[0].KeyID

	keys := p.getKeys(kid)
	if len(keys) == 0 {
		// kid miss — try re-fetching JWKS.
		p.logger.DebugContext(ctx, "JWKS kid miss, re-fetching", "kid", kid)
		p.metrics.OIDCJWKSCacheMisses.Add(ctx, 1)
		if err := p.fetchJWKS(ctx); err != nil {
			return nil, fmt.Errorf("JWKS re-fetch: %w", err)
		}
		keys = p.getKeys(kid)
		if len(keys) == 0 {
			return nil, fmt.Errorf("no matching key for kid %q", kid)
		}
	} else {
		p.metrics.OIDCJWKSCacheHits.Add(ctx, 1)
	}

	// Verify signature and extract claims.
	var claims idTokenClaims
	if err := tok.Claims(keys[0].Key, &claims); err != nil {
		return nil, fmt.Errorf("verify ID token signature: %w", err)
	}

	// Validate issuer.
	if claims.Issuer != p.issuer {
		return nil, fmt.Errorf("ID token issuer %q does not match expected %q", claims.Issuer, p.issuer)
	}

	// Validate audience.
	if !claims.Audience.Contains(p.clientID) {
		return nil, fmt.Errorf("ID token audience does not contain client_id %q", p.clientID)
	}

	// Validate expiry.
	if claims.Expiry == nil || claims.Expiry.Time().Before(time.Now()) {
		return nil, fmt.Errorf("ID token is expired")
	}

	// Validate nonce.
	if claims.Nonce != expectedNonce {
		return nil, fmt.Errorf("ID token nonce mismatch")
	}

	// Validate subject is present.
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

func (p *Provider) getKeys(kid string) []jose.JSONWebKey {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.jwks == nil {
		return nil
	}
	if kid == "" {
		// No kid — return all keys. The caller will try the first.
		return p.jwks.Keys
	}
	return p.jwks.Key(kid)
}
