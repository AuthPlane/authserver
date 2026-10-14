package hcvault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	authcrypto "github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// signingTransitServer is a fake Vault Transit mount holding one key,
// "test-key", backed by priv. Unlike mockTransitServer it really signs, and it
// follows Vault's rules for the request fields: an RSA key signs PSS unless the
// request asks for signature_algorithm=pkcs1v15 (Vault 1.21, checked
// 2026-10-06), and an EC key ignores signature_algorithm. The last sign
// request body is kept for assertions.
type signingTransitServer struct {
	*httptest.Server
	mu       sync.Mutex
	lastSign map[string]interface{}
}

func newSigningTransitServer(t *testing.T, priv crypto.Signer, keyType string) *signingTransitServer {
	t.Helper()
	pubDER, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	s := &signingTransitServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/test-key":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"name":           "test-key",
					"type":           keyType,
					"latest_version": 1,
					"keys": map[string]interface{}{
						"1": map[string]interface{}{"public_key": pubPEM},
					},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/transit/sign/test-key":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode sign body: %v", err)
			}
			s.mu.Lock()
			s.lastSign = body
			s.mu.Unlock()

			if body["prehashed"] != true || body["hash_algorithm"] != "sha2-256" {
				t.Errorf("sign body: want prehashed=true, hash_algorithm=sha2-256; got %v", body)
			}
			digest, err := base64.StdEncoding.DecodeString(body["input"].(string))
			if err != nil {
				t.Errorf("decode input: %v", err)
			}

			var sig []byte
			switch k := priv.(type) {
			case *rsa.PrivateKey:
				if body["signature_algorithm"] == "pkcs1v15" {
					sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest)
				} else {
					sig, err = rsa.SignPSS(rand.Reader, k, crypto.SHA256, digest, nil)
				}
			case *ecdsa.PrivateKey:
				sig, err = ecdsa.SignASN1(rand.Reader, k, digest)
			}
			if err != nil {
				t.Errorf("fake vault sign: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"signature":   "vault:v1:" + base64.StdEncoding.EncodeToString(sig),
					"key_version": 1,
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{"not found: " + r.URL.Path}})
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *signingTransitServer) lastSignBody() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSign
}

// signAndVerifyAccessToken signs an access token with sk exactly as the token
// issuers do, then verifies it twice: with the server's own verifier against a
// JWKS built from sk's public key, and directly with the standard library
// (PKCS#1 v1.5 for RS256, ECDSA for ES256), so a signature in the wrong scheme
// cannot pass by way of a shared mistake in authserver code.
func signAndVerifyAccessToken(t *testing.T, sk *output.SigningKey) {
	t.Helper()
	now := time.Now()
	kp := &authcrypto.KeyPair{
		PrivateKey: sk.PrivateKey,
		PublicKey:  sk.PublicKey,
		Algorithm:  jose.SignatureAlgorithm(sk.Algorithm),
		KeyID:      sk.KeyID,
	}
	token, err := authcrypto.SignAccessTokenContext(context.Background(), kp, authcrypto.AccessTokenClaims{
		Issuer:   "https://as.example",
		Subject:  "user-1",
		Audience: []string{"https://rs.example/mcp"},
		ClientID: "client-1",
		JTI:      "jti-1",
		IssuedAt: now.Unix(),
		Expiry:   now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}

	jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: sk.PublicKey, KeyID: sk.KeyID, Algorithm: sk.Algorithm, Use: "sig",
	}}}
	if _, verifyErr := authcrypto.VerifyAccessToken(token, jwks); verifyErr != nil {
		t.Errorf("authserver verifier rejected the %s token: %v", sk.Algorithm, verifyErr)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch pub := sk.PublicKey.(type) {
	case *rsa.PublicKey:
		if verifyErr := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); verifyErr != nil {
			t.Errorf("RS256 signature is not valid PKCS#1 v1.5: %v", verifyErr)
		}
	case *ecdsa.PublicKey:
		if len(sig) != 64 {
			t.Fatalf("ES256 signature is %d bytes, want 64 (raw R||S)", len(sig))
		}
		der, derErr := rawToDER(sig)
		if derErr != nil {
			t.Fatalf("raw to DER: %v", derErr)
		}
		if !ecdsa.VerifyASN1(pub, digest[:], der) {
			t.Error("ES256 signature does not verify")
		}
	default:
		t.Fatalf("unexpected public key type %T", sk.PublicKey)
	}
}

func newSigningStore(t *testing.T, addr, algorithm string) *Store {
	t.Helper()
	return NewStore(newTestClient(t, addr), "test-key", algorithm, observability.NewNoop())
}

// Vault signs with PSS unless told otherwise, while the token header
// and the JWKS say RS256 (PKCS#1 v1.5). Every RS256 token from Vault Transit
// failed verification.
func TestVaultTransit_RS256TokenVerifies(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	srv := newSigningTransitServer(t, priv, "rsa-2048")

	sk, err := newSigningStore(t, srv.URL, "RS256").LoadCurrent(context.Background())
	if err != nil {
		t.Fatalf("LoadCurrent: %v", err)
	}
	signAndVerifyAccessToken(t, sk)

	if got := srv.lastSignBody()["signature_algorithm"]; got != "pkcs1v15" {
		t.Errorf("sign request signature_algorithm = %v, want pkcs1v15", got)
	}
}

func TestVaultTransit_ES256TokenVerifies(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	srv := newSigningTransitServer(t, priv, "ecdsa-p256")

	sk, err := newSigningStore(t, srv.URL, "ES256").LoadCurrent(context.Background())
	if err != nil {
		t.Fatalf("LoadCurrent: %v", err)
	}
	signAndVerifyAccessToken(t, sk)

	if got, ok := srv.lastSignBody()["signature_algorithm"]; ok {
		t.Errorf("EC sign request carries signature_algorithm=%v; want the field absent", got)
	}
}

// A Transit key whose type does not match signing.algorithm cannot produce a
// verifiable token. The store refuses to hand out such a key — from every
// read path — instead of publishing e.g. kty=EC with alg=RS256.
func TestVaultTransit_KeyTypeMismatchFailsClosed(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	// The error is what the operator acts on at boot, so it must offer only
	// remedies that exist: an algorithm setting only when the key's type maps
	// to a supported algorithm, and always a new key under the full key_name.
	tests := []struct {
		name          string
		priv          crypto.Signer
		keyType       string
		algorithm     string
		algorithmHint string // "" when no supported algorithm fits the key
	}{
		{"EC P-256 key, RS256 configured", p256, "ecdsa-p256", "RS256", "set signing.algorithm to ES256"},
		{"RSA key, ES256 configured", rsaKey, "rsa-2048", "ES256", "set signing.algorithm to RS256"},
		{"EC P-384 key, ES256 configured", p384, "ecdsa-p384", "ES256", ""},
		{"ed25519 key, ES256 configured", edKey, "ed25519", "ES256", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newSigningTransitServer(t, tt.priv, tt.keyType)
			store := newSigningStore(t, srv.URL, tt.algorithm)
			ctx := context.Background()

			sk, err := store.LoadCurrent(ctx)
			if !errors.Is(err, ErrKeyAlgorithmMismatch) {
				t.Fatalf("LoadCurrent = (%v, %v), want ErrKeyAlgorithmMismatch", sk, err)
			}
			msg := err.Error()
			if tt.algorithmHint != "" && !strings.Contains(msg, tt.algorithmHint) {
				t.Errorf("error %q does not offer %q", msg, tt.algorithmHint)
			}
			if tt.algorithmHint == "" && strings.Contains(msg, "set signing.algorithm") {
				t.Errorf("error %q offers an algorithm setting no supported algorithm can satisfy", msg)
			}
			if want := "signing.vault_transit.key_name"; !strings.Contains(msg, want) {
				t.Errorf("error %q does not name %s", msg, want)
			}
			if keys, err := store.ListActive(ctx); !errors.Is(err, ErrKeyAlgorithmMismatch) {
				t.Errorf("ListActive = (%v, %v), want ErrKeyAlgorithmMismatch", keys, err)
			}
		})
	}
}
