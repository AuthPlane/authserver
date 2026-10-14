package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/adapters/hcvault"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// transitKeyServer answers GET /v1/transit/keys/signing-key with status. On
// 200 it returns one version holding an EC P-256 public key under the given
// Transit type, which lets a test present a key whose type disagrees with
// signing.algorithm.
func transitKeyServer(t *testing.T, status int, keyType string) *httptest.Server {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet || r.URL.Path != "/v1/transit/keys/signing-key" {
			t.Errorf("unexpected Vault call at startup: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{"test status"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"name":           "signing-key",
				"type":           keyType,
				"latest_version": 1,
				"keys":           map[string]interface{}{"1": map[string]interface{}{"public_key": pubPEM}},
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func vaultSigningConfig(addr, algorithm string) *config.Config {
	cfg := &config.Config{}
	cfg.Signing.KeyStore = "vault_transit"
	cfg.Signing.Algorithm = algorithm
	cfg.Signing.VaultTransit = config.VaultTransitConfig{
		Address: addr,
		Token:   "test-token",
		Mount:   "transit",
		KeyName: "signing-key",
		Timeout: 5 * time.Second,
	}
	return cfg
}

// A Transit key whose type does not match signing.algorithm can never
// sign a verifiable token, so Open refuses to start. When the key cannot be
// read (Vault down, key not created yet) Open starts as before and the first
// signing request decides — a Vault outage at boot must not become a boot
// failure.
func TestOpen_VaultTransit_KeyTypeCheckAtStartup(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		keyType      string
		algorithm    string
		wantMismatch bool
	}{
		{"matching key starts", http.StatusOK, "ecdsa-p256", "ES256", false},
		{"EC key with RS256 refuses to start", http.StatusOK, "ecdsa-p256", "RS256", true},
		{"key not created yet starts", http.StatusNotFound, "", "ES256", false},
		{"vault error starts", http.StatusInternalServerError, "", "ES256", false},
	}
	obs := observability.NewNoop()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := transitKeyServer(t, tt.status, tt.keyType)
			cfg := vaultSigningConfig(srv.URL, tt.algorithm)

			res, err := Open(context.Background(), cfg, nil, nil, obs)
			checkOpenResult(t, res, err, tt.wantMismatch)
		})

		// Same check when vault_transit_encrypt data encryption targets the
		// same Vault address and mount.
		t.Run(tt.name+" (vault_transit_encrypt on the same Vault)", func(t *testing.T) {
			srv := transitKeyServer(t, tt.status, tt.keyType)
			cfg := vaultSigningConfig(srv.URL, tt.algorithm)
			client, err := hcvault.NewClient(context.Background(), hcvault.ClientConfig{
				Address: srv.URL, Token: "test-token", Mount: "transit", Timeout: 5 * time.Second,
			}, obs)
			if err != nil {
				t.Fatalf("create client: %v", err)
			}
			t.Cleanup(client.Close)
			var enc output.DataEncryptor = hcvault.NewEncryptor(client, "data-key", obs)

			res, err := Open(context.Background(), cfg, nil, enc, obs)
			checkOpenResult(t, res, err, tt.wantMismatch)
		})
	}
}

// The startup check must not hold boot for the full Vault client timeout when
// Vault accepts the connection but never answers (a blackholed or hung Vault):
// it gives up after startupKeyCheckTimeout and boot continues.
func TestOpen_VaultTransit_StartupCheckIsBounded(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })

	prev := startupKeyCheckTimeout
	startupKeyCheckTimeout = 200 * time.Millisecond
	t.Cleanup(func() { startupKeyCheckTimeout = prev })

	cfg := vaultSigningConfig(srv.URL, "ES256")
	cfg.Signing.VaultTransit.Timeout = 30 * time.Second

	start := time.Now()
	res, err := Open(context.Background(), cfg, nil, nil, observability.NewNoop())
	elapsed := time.Since(start)
	checkOpenResult(t, res, err, false)
	if elapsed > 5*time.Second {
		t.Fatalf("Open took %s with a hung Vault; want about startupKeyCheckTimeout (%s)", elapsed, startupKeyCheckTimeout)
	}
}

// The test above shortens the bound, so it cannot see the default drift.
func TestStartupKeyCheckTimeout_DefaultIsShort(t *testing.T) {
	if startupKeyCheckTimeout <= 0 || startupKeyCheckTimeout > 2*time.Second {
		t.Fatalf("startupKeyCheckTimeout = %s, want > 0 and <= 2s", startupKeyCheckTimeout)
	}
}

func checkOpenResult(t *testing.T, res *OpenResult, err error, wantMismatch bool) {
	t.Helper()
	if res != nil && res.Closer != nil {
		t.Cleanup(func() { _ = res.Closer.Close() })
	}
	if wantMismatch {
		if !errors.Is(err, hcvault.ErrKeyAlgorithmMismatch) {
			t.Fatalf("Open error = %v, want ErrKeyAlgorithmMismatch", err)
		}
		if res != nil {
			t.Errorf("Open returned a result alongside the error")
		}
		return
	}
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if res == nil || res.Store == nil {
		t.Fatal("Open returned no store")
	}
}
