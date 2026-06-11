package hcvault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// mockTransitServer creates a mock Vault Transit server with an ECDSA key.
func mockTransitServer(t *testing.T) (*httptest.Server, *ecdsa.PrivateKey) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	var keyVersion atomic.Int32
	keyVersion.Store(1)
	var keyCreated atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		// GET /v1/transit/keys/<name> — read key
		case r.Method == "GET" && r.URL.Path == "/v1/transit/keys/test-key":
			if !keyCreated.Load() {
				w.WriteHeader(404)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"errors": []string{"no key found"},
				})
				return
			}
			v := int(keyVersion.Load())
			keys := map[string]interface{}{}
			for i := 1; i <= v; i++ {
				keys[itoa(i)] = map[string]interface{}{
					"public_key":    pubPEM,
					"creation_time": "2026-02-23T00:00:00Z",
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"name":           "test-key",
					"type":           "ecdsa-p256",
					"latest_version": v,
					"keys":           keys,
				},
			})

		// POST /v1/transit/keys/<name> — create key
		case r.Method == "POST" && r.URL.Path == "/v1/transit/keys/test-key":
			keyCreated.Store(true)
			keyVersion.Store(1)
			w.WriteHeader(204)

		// POST /v1/transit/keys/<name>/rotate — rotate key
		case r.Method == "POST" && r.URL.Path == "/v1/transit/keys/test-key/rotate":
			keyVersion.Add(1)
			w.WriteHeader(204)

		// POST /v1/transit/sign/<name> — sign
		case r.Method == "POST" && r.URL.Path == "/v1/transit/sign/test-key":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"signature":   "vault:v1:dGVzdHNpZ25hdHVyZWRhdGE=",
					"key_version": 1,
				},
			})

		default:
			w.WriteHeader(404)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{"not found: " + r.URL.Path},
			})
		}
	}))
	return srv, priv
}

func itoa(i int) string {
	s := ""
	if i == 0 {
		return "0"
	}
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}

func TestStore_LoadCurrent_KeyNotFound(t *testing.T) {
	srv, _ := mockTransitServer(t)
	defer srv.Close()

	obs := observability.NewNoop()
	c, err := NewClient(context.Background(), ClientConfig{
		Address: srv.URL,
		Token:   "test-token",
	}, obs)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer c.Close()

	store := NewStore(c, "test-key", "ES256", obs)

	// Before key is created, LoadCurrent returns nil, nil.
	key, err := store.LoadCurrent(context.Background())
	if err != nil {
		t.Fatalf("LoadCurrent: %v", err)
	}
	if key != nil {
		t.Error("expected nil key before creation")
	}
}

func TestStore_Save_CreatesKey(t *testing.T) {
	srv, _ := mockTransitServer(t)
	defer srv.Close()

	obs := observability.NewNoop()
	c, err := NewClient(context.Background(), ClientConfig{
		Address: srv.URL,
		Token:   "test-token",
	}, obs)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer c.Close()

	store := NewStore(c, "test-key", "ES256", obs)

	// Save creates the key.
	if saveErr := store.Save(context.Background(), nil); saveErr != nil {
		t.Fatalf("Save (create): %v", saveErr)
	}

	// Now LoadCurrent should return a key.
	key, err := store.LoadCurrent(context.Background())
	if err != nil {
		t.Fatalf("LoadCurrent: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key after creation")
	}
	if key.KeyID != "test-key-v1" {
		t.Errorf("KeyID = %q, want test-key-v1", key.KeyID)
	}
	if key.Algorithm != "ES256" {
		t.Errorf("Algorithm = %q, want ES256", key.Algorithm)
	}
	if key.PublicKey == nil {
		t.Error("PublicKey is nil")
	}
	if key.PrivateKey == nil {
		t.Error("PrivateKey (VaultSigner) is nil")
	}
}

func TestStore_Save_RotatesKey(t *testing.T) {
	srv, _ := mockTransitServer(t)
	defer srv.Close()

	obs := observability.NewNoop()
	c, err := NewClient(context.Background(), ClientConfig{
		Address: srv.URL,
		Token:   "test-token",
	}, obs)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer c.Close()

	store := NewStore(c, "test-key", "ES256", obs)

	// Create key first.
	if saveErr := store.Save(context.Background(), nil); saveErr != nil {
		t.Fatalf("Save (create): %v", saveErr)
	}

	// Rotate.
	if rotateErr := store.Save(context.Background(), nil); rotateErr != nil {
		t.Fatalf("Save (rotate): %v", rotateErr)
	}

	// Verify current is v2.
	key, err := store.LoadCurrent(context.Background())
	if err != nil {
		t.Fatalf("LoadCurrent: %v", err)
	}
	if key.KeyID != "test-key-v2" {
		t.Errorf("KeyID = %q, want test-key-v2", key.KeyID)
	}
}

func TestStore_LoadPrevious_NoKeyExists(t *testing.T) {
	srv, _ := mockTransitServer(t)
	defer srv.Close()

	obs := observability.NewNoop()
	c, err := NewClient(context.Background(), ClientConfig{
		Address: srv.URL,
		Token:   "test-token",
	}, obs)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer c.Close()

	store := NewStore(c, "test-key", "ES256", obs)

	// No key -> nil.
	key, err := store.LoadPrevious(context.Background())
	if err != nil {
		t.Fatalf("LoadPrevious: %v", err)
	}
	if key != nil {
		t.Error("expected nil when key doesn't exist")
	}
}

func TestStore_LoadPrevious_NoPreviousVersion(t *testing.T) {
	srv, _ := mockTransitServer(t)
	defer srv.Close()

	obs := observability.NewNoop()
	c, err := NewClient(context.Background(), ClientConfig{
		Address: srv.URL,
		Token:   "test-token",
	}, obs)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer c.Close()

	store := NewStore(c, "test-key", "ES256", obs)

	// Create key (v1 only — no previous).
	if saveErr := store.Save(context.Background(), nil); saveErr != nil {
		t.Fatalf("Save: %v", saveErr)
	}

	key, err := store.LoadPrevious(context.Background())
	if err != nil {
		t.Fatalf("LoadPrevious: %v", err)
	}
	if key != nil {
		t.Error("expected nil previous when only v1 exists")
	}
}

func TestStore_LoadPrevious_AfterRotation(t *testing.T) {
	srv, _ := mockTransitServer(t)
	defer srv.Close()

	obs := observability.NewNoop()
	c, err := NewClient(context.Background(), ClientConfig{
		Address: srv.URL,
		Token:   "test-token",
	}, obs)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer c.Close()

	store := NewStore(c, "test-key", "ES256", obs)

	// Create + rotate -> v2 current, v1 previous.
	if saveErr := store.Save(context.Background(), nil); saveErr != nil {
		t.Fatalf("Save (create): %v", saveErr)
	}
	if rotateErr := store.Save(context.Background(), nil); rotateErr != nil {
		t.Fatalf("Save (rotate): %v", rotateErr)
	}

	prev, err := store.LoadPrevious(context.Background())
	if err != nil {
		t.Fatalf("LoadPrevious: %v", err)
	}
	if prev == nil {
		t.Fatal("expected non-nil previous key after rotation")
	}
	if prev.KeyID != "test-key-v1" {
		t.Errorf("previous KeyID = %q, want test-key-v1", prev.KeyID)
	}
}

func TestStore_KeyStoreInterface(t *testing.T) {
	// Verify compile-time interface compliance.
	var _ output.KeyStore = (*Store)(nil)
}

func TestStore_SignerReturnedByLoadCurrent(t *testing.T) {
	srv, _ := mockTransitServer(t)
	defer srv.Close()

	obs := observability.NewNoop()
	c, err := NewClient(context.Background(), ClientConfig{
		Address: srv.URL,
		Token:   "test-token",
	}, obs)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer c.Close()

	store := NewStore(c, "test-key", "ES256", obs)

	if saveErr := store.Save(context.Background(), nil); saveErr != nil {
		t.Fatalf("Save: %v", saveErr)
	}

	key, err := store.LoadCurrent(context.Background())
	if err != nil {
		t.Fatalf("LoadCurrent: %v", err)
	}

	// Verify the signer is a VaultSigner.
	signer, ok := key.PrivateKey.(*VaultSigner)
	if !ok {
		t.Fatalf("PrivateKey is %T, want *VaultSigner", key.PrivateKey)
	}
	if signer.keyName != "test-key" {
		t.Errorf("signer.keyName = %q, want test-key", signer.keyName)
	}
	if signer.keyVersion != 1 {
		t.Errorf("signer.keyVersion = %d, want 1", signer.keyVersion)
	}
}

func TestIsNotFound(t *testing.T) {
	ve404 := &VaultError{StatusCode: 404, Path: "/test"}
	if !isNotFound(ve404) {
		t.Error("expected 404 to be isNotFound")
	}

	ve403 := &VaultError{StatusCode: 403, Path: "/test"}
	if isNotFound(ve403) {
		t.Error("expected 403 to NOT be isNotFound")
	}

	other := context.DeadlineExceeded
	if isNotFound(other) {
		t.Error("expected non-VaultError to NOT be isNotFound")
	}
}
