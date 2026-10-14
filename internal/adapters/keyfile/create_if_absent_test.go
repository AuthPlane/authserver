package keyfile

import (
	"context"
	"testing"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

func testKey(t *testing.T, kid string) *output.SigningKey {
	t.Helper()
	kp, err := crypto.GenerateKeyPair("ES256", kid)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &output.SigningKey{PrivateKey: kp.PrivateKey, PublicKey: kp.PublicKey, Algorithm: "ES256", KeyID: kid}
}

// First use writes the key only when there is none: an existing current key
// is never replaced or rotated to previous.
func TestStore_CreateIfAbsent_KeepsAnExistingKey(t *testing.T) {
	store, err := New(t.TempDir(), observability.NewNoop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	if createErr := store.CreateIfAbsent(ctx, testKey(t, "first")); createErr != nil {
		t.Fatalf("CreateIfAbsent: %v", createErr)
	}
	if createErr := store.CreateIfAbsent(ctx, testKey(t, "second")); createErr != nil {
		t.Fatalf("CreateIfAbsent again: %v", createErr)
	}
	cur, err := store.LoadCurrent(ctx)
	if err != nil || cur == nil || cur.KeyID != "first" {
		t.Fatalf("LoadCurrent = %v, %v; want first", cur, err)
	}
	if prev, err := store.LoadPrevious(ctx); err != nil || prev != nil {
		t.Fatalf("LoadPrevious = %v, %v; want none: first use never rotates", prev, err)
	}
}
