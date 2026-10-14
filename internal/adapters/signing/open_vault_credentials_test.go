package signing

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/authplane/authserver/internal/adapters/encryption"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
)

const (
	sharedVaultDataToken    = "data-encryption-token"
	sharedVaultSigningToken = "signing-token"
	sharedVaultSigningKey   = "authserver-signing"
	sharedVaultDataKey      = "authserver-data"
)

// sharedVault fakes one Vault server that holds both the signing key and the
// data-encryption key, with least-privilege policies: the signing credential
// may only read and sign with the signing key, the data credential may only
// encrypt with the data key. Anything else is answered 403, as Vault does.
// Every request's X-Vault-Token is recorded per method and path.
type sharedVault struct {
	srv    *httptest.Server
	pubPEM string

	mu     sync.Mutex
	tokens map[string][]string // "METHOD /path" -> X-Vault-Token values seen
}

func newSharedVault(t *testing.T) *sharedVault {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	v := &sharedVault{
		pubPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		tokens: map[string][]string{},
	}
	v.srv = httptest.NewServer(http.HandlerFunc(v.serve))
	t.Cleanup(v.srv.Close)
	return v
}

func (v *sharedVault) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	token := r.Header.Get("X-Vault-Token")
	route := r.Method + " " + r.URL.Path
	v.mu.Lock()
	v.tokens[route] = append(v.tokens[route], token)
	v.mu.Unlock()

	deny := func() {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
	}

	switch route {
	case "POST /v1/auth/approle/login":
		var body struct {
			RoleID string `json:"role_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.RoleID != "signing-role" {
			deny()
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": sharedVaultSigningToken, "lease_duration": 3600},
		})

	case "GET /v1/transit/keys/" + sharedVaultSigningKey:
		if token != sharedVaultSigningToken {
			deny()
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"name":           sharedVaultSigningKey,
				"type":           "ecdsa-p256",
				"latest_version": 1,
				"keys": map[string]any{
					"1": map[string]any{"public_key": v.pubPEM, "creation_time": "2026-10-12T00:00:00Z"},
				},
			},
		})

	case "POST /v1/transit/sign/" + sharedVaultSigningKey:
		if token != sharedVaultSigningToken {
			deny()
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"signature": "vault:v1:c2lnbmF0dXJl", "key_version": 1},
		})

	case "POST /v1/transit/encrypt/" + sharedVaultDataKey:
		if token != sharedVaultDataToken {
			deny()
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"ciphertext": "vault:v1:Y2lwaGVydGV4dA=="},
		})

	default:
		deny()
	}
}

// tokensFor returns the X-Vault-Token values seen on requests whose route
// contains substr.
func (v *sharedVault) tokensFor(substr string) []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []string
	for route, toks := range v.tokens {
		if strings.Contains(route, substr) {
			out = append(out, toks...)
		}
	}
	return out
}

// With vault_transit_encrypt data encryption and vault_transit signing on the
// same Vault address and mount but with separate credentials, every signing
// request must carry the signing credential. Signing that ran under the data
// credential would be denied by a least-privilege policy (403), failing token
// issuance and the JWKS endpoint.
func TestOpen_VaultTransit_SigningUsesOwnCredentialsOnSharedVault(t *testing.T) {
	cases := []struct {
		name       string
		setSigning func(c *config.VaultTransitConfig)
	}{
		{
			name:       "signing token",
			setSigning: func(c *config.VaultTransitConfig) { c.Token = sharedVaultSigningToken },
		},
		{
			name: "signing approle",
			setSigning: func(c *config.VaultTransitConfig) {
				c.AppRole = config.AppRoleConfig{RoleID: "signing-role", SecretID: "signing-secret"}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vault := newSharedVault(t)
			obs := observability.NewNoop()
			ctx := context.Background()

			t.Setenv("TEST_DATA_VAULT_TOKEN", sharedVaultDataToken)
			cfg := &config.Config{}
			cfg.DataEncryption = config.DataEncryptionConfig{
				Driver: "vault_transit_encrypt",
				VaultTransitEncrypt: config.VaultTransitEncryptConfig{
					Address:    vault.srv.URL,
					AuthMethod: "token",
					TokenEnv:   "TEST_DATA_VAULT_TOKEN",
					MountPath:  "transit",
					KeyName:    sharedVaultDataKey,
				},
			}
			cfg.Signing.Algorithm = "ES256"
			cfg.Signing.KeyStore = "vault_transit"
			cfg.Signing.VaultTransit = config.VaultTransitConfig{
				Address: vault.srv.URL,
				Mount:   "transit",
				KeyName: sharedVaultSigningKey,
			}
			tc.setSigning(&cfg.Signing.VaultTransit)

			enc, err := encryption.Open(ctx, cfg.DataEncryption, obs)
			if err != nil {
				t.Fatalf("open data encryptor: %v", err)
			}
			if c, ok := enc.(io.Closer); ok {
				t.Cleanup(func() { _ = c.Close() })
			}

			res, err := Open(ctx, cfg, nil, enc, obs)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if res.Closer != nil {
				t.Cleanup(func() { _ = res.Closer.Close() })
			}

			sk, err := res.Store.LoadCurrent(ctx)
			switch {
			case err != nil:
				t.Errorf("LoadCurrent: %v", err)
			case sk == nil:
				t.Error("LoadCurrent returned no key")
			default:
				digest := sha256.Sum256([]byte("payload"))
				if _, err := sk.PrivateKey.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
					t.Errorf("sign: %v", err)
				}
			}

			signingTokens := vault.tokensFor(sharedVaultSigningKey)
			if len(signingTokens) == 0 {
				t.Fatal("fake Vault saw no signing-key requests")
			}
			for _, tok := range signingTokens {
				if tok != sharedVaultSigningToken {
					t.Errorf("signing-key request carried X-Vault-Token %q, want the signing token %q", tok, sharedVaultSigningToken)
				}
			}

			// Signing owns its client, so Open hands back a Closer for it; the
			// data encryptor's client is closed through the encryptor.
			if res.Closer == nil {
				t.Error("Open returned no Closer for the signing Vault client")
			}

			// The data encryptor keeps its own credential.
			if _, err := enc.Encrypt(ctx, []byte("secret"), "owner"); err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			for _, tok := range vault.tokensFor(sharedVaultDataKey) {
				if tok != sharedVaultDataToken {
					t.Errorf("data-key request carried X-Vault-Token %q, want the data token %q", tok, sharedVaultDataToken)
				}
			}
		})
	}
}
