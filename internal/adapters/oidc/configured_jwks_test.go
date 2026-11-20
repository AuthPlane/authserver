package oidc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/ports/output"
)

// A configured JWKS is parsed once per config value: a set with a skipped
// key must warn once, not on every login.
func TestResolveJWKS_ConfiguredSetWarnsOncePerValue(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good, err := json.Marshal(jose.JSONWebKey{Key: &ecKey.PublicKey, KeyID: "ec", Algorithm: string(jose.ES256), Use: "sig"})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := json.Marshal(map[string]any{"keys": []json.RawMessage{good, json.RawMessage(`{"kty":"future","kid":"later"}`)}})
	if err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	p := &Provider{logger: slog.New(slog.NewTextHandler(&logs, nil))}
	cfg := output.OIDCConfig{Issuer: "https://idp.example", JWKS: doc}

	for range 3 {
		ks, err := p.resolveJWKS(context.Background(), cfg, DiscoveryDoc{})
		if err != nil {
			t.Fatalf("resolveJWKS: %v", err)
		}
		if len(ks.Keys) != 1 || ks.Keys[0].KeyID != "ec" {
			t.Fatalf("keys = %+v, want only kid ec", ks.Keys)
		}
	}
	if got := strings.Count(logs.String(), "configured OIDC JWKS key skipped"); got != 1 {
		t.Fatalf("warned %d times, want once:\n%s", got, logs.String())
	}
	if !strings.Contains(logs.String(), "issuer=https://idp.example") || !strings.Contains(logs.String(), "kid=later") {
		t.Fatalf("warning lacks issuer or kid:\n%s", logs.String())
	}

	// A changed config value is parsed, and warned about, again.
	cfg.JWKS = append([]byte(nil), doc...)
	cfg.JWKS = bytes.Replace(cfg.JWKS, []byte(`"later"`), []byte(`"later2"`), 1)
	if _, err := p.resolveJWKS(context.Background(), cfg, DiscoveryDoc{}); err != nil {
		t.Fatalf("resolveJWKS: %v", err)
	}
	if got := strings.Count(logs.String(), "configured OIDC JWKS key skipped"); got != 2 {
		t.Fatalf("warned %d times after a config change, want 2", got)
	}
}
