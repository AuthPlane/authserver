package crypto

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"io"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type ctxKeyT string

const testCtxKey ctxKeyT = "marker"

// recordingContextSigner wraps a real ECDSA key so the token still verifies,
// and records which signing path go-jose reached and with which context.
type recordingContextSigner struct {
	priv       *ecdsa.PrivateKey
	sawContext bool
	sawMarker  any
}

func (r *recordingContextSigner) Public() crypto.PublicKey { return &r.priv.PublicKey }

func (r *recordingContextSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return r.priv.Sign(rand, digest, opts)
}

func (r *recordingContextSigner) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r.sawContext = true
	r.sawMarker = ctx.Value(testCtxKey)
	return r.priv.Sign(nil, digest, opts)
}

func opaqueKeyPair(t *testing.T) (*KeyPair, *recordingContextSigner) {
	t.Helper()
	base, err := GenerateKeyPair("ES256", "kid-ctx")
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingContextSigner{priv: base.PrivateKey.(*ecdsa.PrivateKey)}
	return &KeyPair{
		PrivateKey: rec,
		PublicKey:  base.PublicKey,
		Algorithm:  jose.ES256,
		KeyID:      base.KeyID,
	}, rec
}

func ctxClaims() AccessTokenClaims {
	now := time.Now()
	return AccessTokenClaims{
		Issuer:   "http://localhost:9000",
		Subject:  "user-123",
		Audience: []string{"https://mcp.example.com"},
		ClientID: "client-abc",
		JTI:      GenerateRandomString(16),
		IssuedAt: now.Unix(),
		Expiry:   now.Add(time.Minute).Unix(),
	}
}

func TestSignAccessTokenContext_ReachesContextSigner(t *testing.T) {
	kp, rec := opaqueKeyPair(t)
	ctx := context.WithValue(context.Background(), testCtxKey, "request-42")

	token, err := SignAccessTokenContext(ctx, kp, ctxClaims())
	if err != nil {
		t.Fatalf("SignAccessTokenContext: %v", err)
	}
	if !rec.sawContext {
		t.Fatal("opaque signer was called through Sign, want SignContext")
	}
	if rec.sawMarker != "request-42" {
		t.Fatalf("SignContext received ctx marker %v, want request-42", rec.sawMarker)
	}

	jwks := BuildJWKS(kp)
	if _, err := VerifyAccessToken(token, &jwks); err != nil {
		t.Fatalf("token signed through SignContext does not verify: %v", err)
	}
}

func TestSignAccessToken_PlainSignerStillWorks(t *testing.T) {
	kp, rec := opaqueKeyPair(t)

	token, err := SignAccessToken(kp, ctxClaims())
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	if !rec.sawContext {
		t.Fatal("SignAccessToken should route through SignContext with a background ctx")
	}
	if rec.sawMarker != nil {
		t.Fatalf("background ctx should carry no marker, got %v", rec.sawMarker)
	}
	jwks := BuildJWKS(kp)
	if _, err := VerifyAccessToken(token, &jwks); err != nil {
		t.Fatalf("token does not verify: %v", err)
	}
}
