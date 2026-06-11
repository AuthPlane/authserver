//go:build integration

package keyfile_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/authplane/authserver/internal/adapters/keyfile"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

func testObs() *observability.Provider {
	return observability.NewNoop()
}

func newTestStore(t *testing.T) *keyfile.Store {
	t.Helper()
	dir := t.TempDir()
	store, err := keyfile.New(dir, testObs())
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	return store
}

func TestStore_LoadCurrent_Empty(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	key, err := store.LoadCurrent(ctx)
	if err != nil {
		t.Fatalf("load current: %v", err)
	}
	if key != nil {
		t.Errorf("expected nil for empty store, got key with kid=%s", key.KeyID)
	}
}

func TestStore_SaveAndLoadCurrent_ES256(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	sk := &output.SigningKey{
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		Algorithm:  "ES256",
		KeyID:      "test-kid-1",
	}

	if err := store.Save(ctx, sk); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := store.LoadCurrent(ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded == nil {
		t.Fatal("loaded nil")
	}
	if loaded.KeyID != "test-kid-1" {
		t.Errorf("kid: got %q, want %q", loaded.KeyID, "test-kid-1")
	}
	if loaded.Algorithm != "ES256" {
		t.Errorf("alg: got %q, want %q", loaded.Algorithm, "ES256")
	}
	if _, ok := loaded.PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("private key type: got %T, want *ecdsa.PrivateKey", loaded.PrivateKey)
	}
}

func TestStore_SaveAndLoadCurrent_RS256(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	sk := &output.SigningKey{
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		Algorithm:  "RS256",
		KeyID:      "rsa-kid-1",
	}

	if err := store.Save(ctx, sk); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := store.LoadCurrent(ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Algorithm != "RS256" {
		t.Errorf("alg: got %q, want %q", loaded.Algorithm, "RS256")
	}
	if _, ok := loaded.PrivateKey.(*rsa.PrivateKey); !ok {
		t.Errorf("private key type: got %T, want *rsa.PrivateKey", loaded.PrivateKey)
	}
}

func TestStore_Rotation(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Save first key.
	priv1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sk1 := &output.SigningKey{
		PrivateKey: priv1,
		PublicKey:  &priv1.PublicKey,
		Algorithm:  "ES256",
		KeyID:      "kid-1",
	}
	if err := store.Save(ctx, sk1); err != nil {
		t.Fatalf("save first: %v", err)
	}

	// No previous yet.
	prev, err := store.LoadPrevious(ctx)
	if err != nil {
		t.Fatalf("load previous (empty): %v", err)
	}
	if prev != nil {
		t.Error("expected no previous key")
	}

	// Save second key — first becomes previous.
	priv2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sk2 := &output.SigningKey{
		PrivateKey: priv2,
		PublicKey:  &priv2.PublicKey,
		Algorithm:  "ES256",
		KeyID:      "kid-2",
	}
	if err := store.Save(ctx, sk2); err != nil {
		t.Fatalf("save second: %v", err)
	}

	// Current should be kid-2.
	current, err := store.LoadCurrent(ctx)
	if err != nil {
		t.Fatalf("load current: %v", err)
	}
	if current.KeyID != "kid-2" {
		t.Errorf("current kid: got %q, want %q", current.KeyID, "kid-2")
	}

	// Previous should be kid-1.
	prev, err = store.LoadPrevious(ctx)
	if err != nil {
		t.Fatalf("load previous: %v", err)
	}
	if prev == nil {
		t.Fatal("expected previous key")
	}
	if prev.KeyID != "kid-1" {
		t.Errorf("previous kid: got %q, want %q", prev.KeyID, "kid-1")
	}
}

func TestStore_PEMPermissions(t *testing.T) {
	dir := t.TempDir()
	store, err := keyfile.New(dir, testObs())
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sk := &output.SigningKey{
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		Algorithm:  "ES256",
		KeyID:      "perm-kid",
	}
	if err := store.Save(context.Background(), sk); err != nil {
		t.Fatalf("save: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "current.pem"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("pem permissions: got %o, want 600", perm)
	}
}

func TestStore_CreateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "keys")
	_, err := keyfile.New(dir, testObs())
	if err != nil {
		t.Fatalf("create store with nested dir: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
}
