package hcvault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
)

// mockEncryptServer creates a mock Vault Transit server for encrypt/decrypt.
func mockEncryptServer(t *testing.T) *httptest.Server {
	t.Helper()

	type entry struct {
		plaintext string
		context   string
	}
	store := make(map[string]entry)
	counter := 0

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]string
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/encrypt/test-key") {
			counter++
			ciphertext := "vault:v1:" + base64.StdEncoding.EncodeToString([]byte(req["plaintext"]+":"+req["context"]))
			store[ciphertext] = entry{
				plaintext: req["plaintext"],
				context:   req["context"],
			}
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"ciphertext": ciphertext,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/decrypt/test-key") {
			e, ok := store[req["ciphertext"]]
			if !ok || e.context != req["context"] {
				http.Error(w, `{"errors":["invalid ciphertext or context"]}`, http.StatusBadRequest)
				return
			}
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"plaintext": e.plaintext,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		http.Error(w, "not found", http.StatusNotFound)
	}))
}

func newTestEncryptor(t *testing.T, serverURL string) *Encryptor {
	t.Helper()
	obs := observability.NewNoop()
	c, err := NewClient(context.Background(), ClientConfig{
		Address: serverURL,
		Token:   "test-token",
		Mount:   "transit",
	}, obs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return NewEncryptor(c, "test-key", obs)
}

func TestEncryptor_EncryptDecrypt_RoundTrip(t *testing.T) {
	srv := mockEncryptServer(t)
	defer srv.Close()

	enc := newTestEncryptor(t, srv.URL)
	ctx := context.Background()

	plaintext := []byte("secret-github-token-ghp_12345")
	ownerContext := "vault:user1:github:conn1"

	ciphertext, err := enc.Encrypt(ctx, plaintext, ownerContext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if !strings.HasPrefix(string(ciphertext), "vault:v1:") {
		t.Fatalf("expected ciphertext to start with 'vault:v1:', got %q", string(ciphertext)[:20])
	}

	decrypted, err := enc.Decrypt(ctx, ciphertext, ownerContext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestEncryptor_ContextSentToVault(t *testing.T) {
	var capturedContext string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]string
		_ = json.Unmarshal(body, &req)
		capturedContext = req["context"]

		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"ciphertext": "vault:v1:test",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	enc := newTestEncryptor(t, srv.URL)
	ctx := context.Background()

	ownerContext := "vault:user1:github:conn1"
	_, err := enc.Encrypt(ctx, []byte("data"), ownerContext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	expectedB64 := base64.StdEncoding.EncodeToString([]byte(ownerContext))
	if capturedContext != expectedB64 {
		t.Fatalf("context not sent correctly: got %q, want %q", capturedContext, expectedB64)
	}
}

func TestEncryptor_VaultUnavailable_ReturnsUnavailableError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"errors":["Vault is sealed"]}`))
	}))
	defer srv.Close()

	enc := newTestEncryptor(t, srv.URL)
	ctx := context.Background()

	_, err := enc.Encrypt(ctx, []byte("data"), "ctx")
	if err == nil {
		t.Fatal("expected error for 503 response")
	}
	if !errors.Is(err, domain.ErrEncryptorUnavailable) {
		t.Fatalf("expected ErrEncryptorUnavailable, got: %v", err)
	}
}

func TestEncryptor_VaultBadRequest_ReturnsEncryptionFailedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":["invalid request"]}`))
	}))
	defer srv.Close()

	enc := newTestEncryptor(t, srv.URL)
	ctx := context.Background()

	_, err := enc.Encrypt(ctx, []byte("data"), "ctx")
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
	if !errors.Is(err, domain.ErrEncryptionFailed) {
		t.Fatalf("expected ErrEncryptionFailed, got: %v", err)
	}
}

func TestEncryptor_DriverName(t *testing.T) {
	obs := observability.NewNoop()
	c, _ := NewClient(context.Background(), ClientConfig{
		Address: "http://localhost:8200",
		Token:   "tok",
	}, obs)
	defer c.Close()

	enc := NewEncryptor(c, "key", obs)
	if enc.DriverName() != "vault_transit_encrypt" {
		t.Errorf("DriverName() = %q, want vault_transit_encrypt", enc.DriverName())
	}
}
