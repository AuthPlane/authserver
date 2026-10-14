//go:build integration_vault

// Real-Vault tests for the Transit signing path. Every other test in this
// package uses an httptest fake, and a fake encodes its author's assumptions
// about Vault: RS256 over Transit shipped broken because nothing checked what
// a real Vault signs. Run with `make test-integration-vault`, or against any
// Vault with a transit mount at "transit":
//
//	AUTHPLANE_TEST_VAULT_ADDR=http://127.0.0.1:8200 AUTHPLANE_TEST_VAULT_TOKEN=root \
//	  go test ./internal/adapters/hcvault/ -tags=integration_vault -run RealVault -v

package hcvault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/observability"
)

func realVaultClient(t *testing.T) *Client {
	t.Helper()
	addr, token := os.Getenv("AUTHPLANE_TEST_VAULT_ADDR"), os.Getenv("AUTHPLANE_TEST_VAULT_TOKEN")
	if addr == "" || token == "" {
		t.Skip("AUTHPLANE_TEST_VAULT_ADDR and AUTHPLANE_TEST_VAULT_TOKEN are not set")
	}
	c, err := NewClient(context.Background(), ClientConfig{
		Address: addr, Token: token, Mount: "transit", Timeout: 10 * time.Second,
	}, observability.NewNoop())
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

// uniqueKeyName keeps runs against a long-lived Vault from reusing a key.
func uniqueKeyName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// Tokens signed through a real Transit key verify, checked by the server's
// verifier and independently by the standard library (signAndVerifyAccessToken).
func TestRealVault_SignedTokensVerify(t *testing.T) {
	c := realVaultClient(t)
	ctx := context.Background()

	tests := []struct {
		keyType   string
		algorithm string
	}{
		{"ecdsa-p256", "ES256"},
		{"rsa-2048", "RS256"},
		{"rsa-4096", "RS256"},
	}
	for _, tt := range tests {
		t.Run(tt.keyType+"/"+tt.algorithm, func(t *testing.T) {
			name := uniqueKeyName("authserver-test-" + tt.keyType)
			if err := c.CreateKey(ctx, name, tt.keyType); err != nil {
				t.Fatalf("create transit key: %v", err)
			}
			sk, err := NewStore(c, name, tt.algorithm, observability.NewNoop()).LoadCurrent(ctx)
			if err != nil {
				t.Fatalf("LoadCurrent: %v", err)
			}
			signAndVerifyAccessToken(t, sk)
		})
	}
}

// A key the store creates itself (first use, RS256) gets a type that signs
// verifiable RS256 tokens.
func TestRealVault_CreatedRS256KeyVerifies(t *testing.T) {
	c := realVaultClient(t)
	ctx := context.Background()
	store := NewStore(c, uniqueKeyName("authserver-test-created"), "RS256", observability.NewNoop())

	if err := store.Save(ctx, nil); err != nil {
		t.Fatalf("Save (create): %v", err)
	}
	sk, err := store.LoadCurrent(ctx)
	if err != nil {
		t.Fatalf("LoadCurrent: %v", err)
	}
	signAndVerifyAccessToken(t, sk)
}

// A real Transit key of the wrong type is refused, including ed25519, whose
// public key Vault returns in a form the PEM parser does not read.
func TestRealVault_KeyTypeMismatchFailsClosed(t *testing.T) {
	c := realVaultClient(t)
	ctx := context.Background()

	tests := []struct {
		keyType   string
		algorithm string
	}{
		{"ecdsa-p256", "RS256"},
		{"rsa-2048", "ES256"},
		{"ecdsa-p384", "ES256"},
		{"ed25519", "ES256"},
	}
	for _, tt := range tests {
		t.Run(tt.keyType+"/"+tt.algorithm, func(t *testing.T) {
			name := uniqueKeyName("authserver-test-" + tt.keyType)
			if err := c.CreateKey(ctx, name, tt.keyType); err != nil {
				t.Fatalf("create transit key: %v", err)
			}
			sk, err := NewStore(c, name, tt.algorithm, observability.NewNoop()).LoadCurrent(ctx)
			if !errors.Is(err, ErrKeyAlgorithmMismatch) {
				t.Fatalf("LoadCurrent = (%v, %v), want ErrKeyAlgorithmMismatch", sk, err)
			}
		})
	}
}
