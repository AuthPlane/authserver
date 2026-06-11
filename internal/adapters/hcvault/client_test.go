package hcvault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/observability"
)

func TestNewClient_RequiresAddress(t *testing.T) {
	obs := observability.NewNoop()
	_, err := NewClient(context.Background(), ClientConfig{}, obs)
	if err == nil {
		t.Fatal("expected error for missing address")
	}
}

func TestNewClient_RequiresAuth(t *testing.T) {
	obs := observability.NewNoop()
	_, err := NewClient(context.Background(), ClientConfig{
		Address: "http://localhost:8200",
	}, obs)
	if err == nil {
		t.Fatal("expected error for missing auth")
	}
}

func TestNewClient_StaticToken(t *testing.T) {
	obs := observability.NewNoop()
	c, err := NewClient(context.Background(), ClientConfig{
		Address: "http://localhost:8200",
		Token:   "test-token",
	}, obs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer c.Close()

	if c.getToken() != "test-token" {
		t.Errorf("token = %q, want test-token", c.getToken())
	}
	if c.mount != "transit" {
		t.Errorf("mount = %q, want transit", c.mount)
	}
}

func TestNewClient_CustomMount(t *testing.T) {
	obs := observability.NewNoop()
	c, err := NewClient(context.Background(), ClientConfig{
		Address: "http://localhost:8200",
		Token:   "tok",
		Mount:   "custom-transit",
	}, obs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer c.Close()

	if c.mount != "custom-transit" {
		t.Errorf("mount = %q, want custom-transit", c.mount)
	}
}

func TestClient_Sign_MockServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/transit/sign/mykey" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", 404)
			return
		}
		if r.Header.Get("X-Vault-Token") != "test-token" {
			t.Error("missing or wrong vault token header")
		}

		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if prehashed, ok := body["prehashed"].(bool); !ok || !prehashed {
			t.Error("expected prehashed=true")
		}

		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"signature":   "vault:v1:dGVzdHNpZ25hdHVyZQ==",
				"key_version": 1,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	obs := observability.NewNoop()
	c, err := NewClient(context.Background(), ClientConfig{
		Address: srv.URL,
		Token:   "test-token",
		Timeout: 5 * time.Second,
	}, obs)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer c.Close()

	sig, err := c.Sign(context.Background(), "mykey", "dGVzdA==", "sha2-256", 0)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sig != "vault:v1:dGVzdHNpZ25hdHVyZQ==" {
		t.Errorf("sig = %q, unexpected", sig)
	}
}

func TestClient_ReadKey_MockServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/transit/keys/mykey" {
			http.Error(w, "not found", 404)
			return
		}
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"name":           "mykey",
				"type":           "ecdsa-p256",
				"latest_version": 1,
				"keys": map[string]interface{}{
					"1": map[string]interface{}{
						"public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----\n",
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
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

	raw, err := c.ReadKey(context.Background(), "mykey")
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if len(raw) == 0 {
		t.Error("expected non-empty response")
	}
}

func TestClient_VaultError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
	}))
	defer srv.Close()

	obs := observability.NewNoop()
	c, err := NewClient(context.Background(), ClientConfig{
		Address: srv.URL,
		Token:   "bad-token",
	}, obs)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer c.Close()

	_, err = c.ReadKey(context.Background(), "mykey")
	if err == nil {
		t.Fatal("expected error for 403")
	}

	ve, ok := err.(*VaultError)
	if !ok {
		t.Fatalf("expected *VaultError, got %T", err)
	}
	if ve.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403", ve.StatusCode)
	}
}

func TestClient_AppRoleLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["role_id"] != "test-role" || body["secret_id"] != "test-secret" {
				w.WriteHeader(401)
				return
			}
			resp := map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "new-token-from-approle",
					"lease_duration": 3600,
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		http.Error(w, "not found", 404)
	}))
	defer srv.Close()

	obs := observability.NewNoop()
	c, err := NewClient(context.Background(), ClientConfig{
		Address: srv.URL,
		AppRole: &AppRoleAuth{
			RoleID:   "test-role",
			SecretID: "test-secret",
			Mount:    "approle",
		},
	}, obs)
	if err != nil {
		t.Fatalf("create client with approle: %v", err)
	}
	defer c.Close()

	if c.getToken() != "new-token-from-approle" {
		t.Errorf("token = %q, want new-token-from-approle", c.getToken())
	}
}

func TestVaultError_Error(t *testing.T) {
	e := &VaultError{StatusCode: 404, Body: "not found", Path: "/v1/test"}
	msg := e.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
}

func TestClient_Encrypt_MockServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/transit/encrypt/data-key" {
			http.Error(w, "not found", 404)
			return
		}
		if r.Header.Get("X-Vault-Token") != "test-token" {
			t.Error("missing or wrong vault token header")
		}

		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["plaintext"] == "" {
			t.Error("expected non-empty plaintext")
		}

		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"ciphertext": "vault:v1:encrypted-data",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
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

	ct, err := c.Encrypt(context.Background(), "data-key", "cGxhaW50ZXh0", "Y29udGV4dA==")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if ct != "vault:v1:encrypted-data" {
		t.Errorf("ciphertext = %q, unexpected", ct)
	}
}

func TestClient_Decrypt_MockServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/transit/decrypt/data-key" {
			http.Error(w, "not found", 404)
			return
		}

		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["ciphertext"] == "" {
			t.Error("expected non-empty ciphertext")
		}

		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"plaintext": "cGxhaW50ZXh0",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
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

	pt, err := c.Decrypt(context.Background(), "data-key", "vault:v1:encrypted", "Y29udGV4dA==")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if pt != "cGxhaW50ZXh0" {
		t.Errorf("plaintext = %q, unexpected", pt)
	}
}

func TestClient_ResponseTooLarge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write more than maxVaultResponseLen (1 MiB).
		_, _ = w.Write([]byte(strings.Repeat("x", maxVaultResponseLen+1)))
	}))
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

	_, err = c.request(context.Background(), "GET", "/v1/transit/keys/mykey", nil)
	if err == nil {
		t.Fatal("expected error for oversized response")
	}
	if !strings.Contains(err.Error(), "exceeds max size") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClient_ResponseWithinLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"data": map[string]interface{}{"key": "value"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
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

	resp, err := c.request(context.Background(), "GET", "/v1/transit/keys/mykey", nil)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if len(resp) == 0 {
		t.Error("expected non-empty response")
	}
}

func TestClient_AddressAndMount(t *testing.T) {
	obs := observability.NewNoop()
	c, err := NewClient(context.Background(), ClientConfig{
		Address: "http://vault:8200",
		Token:   "tok",
		Mount:   "my-transit",
	}, obs)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer c.Close()

	if c.Address() != "http://vault:8200" {
		t.Errorf("Address() = %q, want http://vault:8200", c.Address())
	}
	if c.Mount() != "my-transit" {
		t.Errorf("Mount() = %q, want my-transit", c.Mount())
	}
}
