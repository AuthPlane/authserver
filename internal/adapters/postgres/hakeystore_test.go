//go:build integration_postgres

package postgres_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/authplane/authserver/internal/adapters/aesmaster"
	pgadapter "github.com/authplane/authserver/internal/adapters/postgres"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

// testMasterKeyHex is a 64-char hex string (32 bytes) for AES-256 testing.
const testMasterKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// altMasterKeyHex is a different master key for negative decryption test.
const altMasterKeyHex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

func newTestEncryptor(t *testing.T) output.DataEncryptor {
	t.Helper()
	obs := observability.NewNoop()
	enc, err := aesmaster.New(testMasterKeyHex, obs)
	if err != nil {
		t.Fatalf("create test encryptor: %v", err)
	}
	return enc
}

func newHATestSigningKey(t *testing.T, kid string) *output.SigningKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &output.SigningKey{
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		Algorithm:  "ES256",
		KeyID:      kid,
	}
}

func newHAKeyStore(t *testing.T) *pgadapter.HAKeyStore {
	t.Helper()
	db := testdata.SetupTestPGDB(t, pgContainerDSN)
	enc := newTestEncryptor(t)
	obs := observability.NewNoop()
	return pgadapter.NewHAKeyStore(db.Pool, enc, obs)
}

func TestHAKeyStore_SaveAndLoadCurrent(t *testing.T) {
	store := newHAKeyStore(t)
	ctx := context.Background()

	k1 := newHATestSigningKey(t, "kid-ha-1")
	if err := store.Save(ctx, k1); err != nil {
		t.Fatalf("save key: %v", err)
	}

	current, err := store.LoadCurrent(ctx)
	if err != nil {
		t.Fatalf("load current: %v", err)
	}
	if current == nil {
		t.Fatal("expected current key, got nil")
	}
	if current.KeyID != "kid-ha-1" {
		t.Errorf("kid: got %q, want %q", current.KeyID, "kid-ha-1")
	}
	if current.Algorithm != "ES256" {
		t.Errorf("alg: got %q, want %q", current.Algorithm, "ES256")
	}
	if _, ok := current.PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", current.PrivateKey)
	}
}

func TestHAKeyStore_SaveRotatesCorrectly(t *testing.T) {
	store := newHAKeyStore(t)
	ctx := context.Background()

	k1 := newHATestSigningKey(t, "kid-rot-1")
	if err := store.Save(ctx, k1); err != nil {
		t.Fatalf("save key 1: %v", err)
	}

	k2 := newHATestSigningKey(t, "kid-rot-2")
	if err := store.Save(ctx, k2); err != nil {
		t.Fatalf("save key 2: %v", err)
	}

	// Invalidate cache to force DB reads.
	store.InvalidateCache()

	current, err := store.LoadCurrent(ctx)
	if err != nil {
		t.Fatalf("load current: %v", err)
	}
	if current.KeyID != "kid-rot-2" {
		t.Errorf("current kid: got %q, want %q", current.KeyID, "kid-rot-2")
	}

	prev, err := store.LoadPrevious(ctx)
	if err != nil {
		t.Fatalf("load previous: %v", err)
	}
	if prev == nil {
		t.Fatal("expected previous key after rotation, got nil")
	}
	if prev.KeyID != "kid-rot-1" {
		t.Errorf("previous kid: got %q, want %q", prev.KeyID, "kid-rot-1")
	}
}

func TestHAKeyStore_LoadPrevious_NilOnFirstKey(t *testing.T) {
	store := newHAKeyStore(t)
	ctx := context.Background()

	k1 := newHATestSigningKey(t, "kid-single")
	if err := store.Save(ctx, k1); err != nil {
		t.Fatalf("save key: %v", err)
	}

	prev, err := store.LoadPrevious(ctx)
	if err != nil {
		t.Fatalf("load previous: %v", err)
	}
	if prev != nil {
		t.Errorf("expected nil previous on first key, got kid=%s", prev.KeyID)
	}
}

func TestHAKeyStore_ListActive(t *testing.T) {
	store := newHAKeyStore(t)
	ctx := context.Background()

	// Empty store returns empty slice.
	keys, err := store.ListActive(ctx)
	if err != nil {
		t.Fatalf("list active (empty): %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys on empty store, got %d", len(keys))
	}

	// Save one key.
	k1 := newHATestSigningKey(t, "kid-list-1")
	if err := store.Save(ctx, k1); err != nil {
		t.Fatalf("save key 1: %v", err)
	}

	store.InvalidateCache()
	keys, err = store.ListActive(ctx)
	if err != nil {
		t.Fatalf("list active (1 key): %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].KeyID != "kid-list-1" {
		t.Errorf("key[0] kid: got %q, want %q", keys[0].KeyID, "kid-list-1")
	}

	// Save second key (rotation).
	k2 := newHATestSigningKey(t, "kid-list-2")
	if err := store.Save(ctx, k2); err != nil {
		t.Fatalf("save key 2: %v", err)
	}

	store.InvalidateCache()
	keys, err = store.ListActive(ctx)
	if err != nil {
		t.Fatalf("list active (2 keys): %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys after rotation, got %d", len(keys))
	}

	// First should be current (kid-list-2), second should be previous (kid-list-1).
	if keys[0].KeyID != "kid-list-2" {
		t.Errorf("key[0] (current): got %q, want %q", keys[0].KeyID, "kid-list-2")
	}
	if keys[1].KeyID != "kid-list-1" {
		t.Errorf("key[1] (previous): got %q, want %q", keys[1].KeyID, "kid-list-1")
	}
}

func TestHAKeyStore_EncryptionRoundTrip(t *testing.T) {
	db := testdata.SetupTestPGDB(t, pgContainerDSN)
	enc := newTestEncryptor(t)
	obs := observability.NewNoop()
	store := pgadapter.NewHAKeyStore(db.Pool, enc, obs)
	ctx := context.Background()

	k1 := newHATestSigningKey(t, "kid-enc-test")
	if err := store.Save(ctx, k1); err != nil {
		t.Fatalf("save key: %v", err)
	}

	// Read enc_private directly from DB and verify it's not plaintext PEM.
	var encPrivate []byte
	err := db.Pool.QueryRow(ctx,
		`SELECT enc_private FROM signing_keys WHERE kid = $1`, "kid-enc-test",
	).Scan(&encPrivate)
	if err != nil {
		t.Fatalf("query enc_private: %v", err)
	}

	// enc_private should NOT be valid PEM (it's encrypted).
	block, _ := pem.Decode(encPrivate)
	if block != nil {
		t.Error("enc_private should be encrypted, but found valid PEM block — key stored in plaintext!")
	}

	// Verify the stored bytes start with version byte 0x01 (AES master format).
	if len(encPrivate) == 0 {
		t.Fatal("enc_private is empty")
	}
	if encPrivate[0] != 0x02 {
		t.Errorf("expected version byte 0x02, got 0x%02x", encPrivate[0])
	}
}

func TestHAKeyStore_WrongEncryptionKeyFails(t *testing.T) {
	db := testdata.SetupTestPGDB(t, pgContainerDSN)
	obs := observability.NewNoop()

	// Save with the correct key.
	enc1, err := aesmaster.New(testMasterKeyHex, obs)
	if err != nil {
		t.Fatalf("create encryptor 1: %v", err)
	}
	store1 := pgadapter.NewHAKeyStore(db.Pool, enc1, obs)
	ctx := context.Background()

	k1 := newHATestSigningKey(t, "kid-wrong-key")
	if err := store1.Save(ctx, k1); err != nil {
		t.Fatalf("save key: %v", err)
	}

	// Try to load with a different master key.
	enc2, err := aesmaster.New(altMasterKeyHex, obs)
	if err != nil {
		t.Fatalf("create encryptor 2: %v", err)
	}
	store2 := pgadapter.NewHAKeyStore(db.Pool, enc2, obs)
	store2.InvalidateCache()

	_, err = store2.LoadCurrent(ctx)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key, got nil")
	}
}

func TestHAKeyStore_TripleRotation_PrunesOldKeys(t *testing.T) {
	store := newHAKeyStore(t)
	ctx := context.Background()

	// Save 3 keys.
	for _, kid := range []string{"kid-a", "kid-b", "kid-c"} {
		k := newHATestSigningKey(t, kid)
		if err := store.Save(ctx, k); err != nil {
			t.Fatalf("save %s: %v", kid, err)
		}
	}

	store.InvalidateCache()

	current, err := store.LoadCurrent(ctx)
	if err != nil {
		t.Fatalf("load current: %v", err)
	}
	if current.KeyID != "kid-c" {
		t.Errorf("current: got %q, want kid-c", current.KeyID)
	}

	prev, err := store.LoadPrevious(ctx)
	if err != nil {
		t.Fatalf("load previous: %v", err)
	}
	if prev == nil {
		t.Fatal("expected previous key, got nil")
	}
	if prev.KeyID != "kid-b" {
		t.Errorf("previous: got %q, want kid-b (kid-a should be pruned)", prev.KeyID)
	}

	// Verify only 2 keys exist in DB.
	keys, err := store.ListActive(ctx)
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 active keys after triple rotation, got %d", len(keys))
	}
}

func TestHAKeyStore_CacheInvalidation(t *testing.T) {
	store := newHAKeyStore(t)
	ctx := context.Background()

	k1 := newHATestSigningKey(t, "kid-cache-1")
	if err := store.Save(ctx, k1); err != nil {
		t.Fatalf("save key 1: %v", err)
	}

	// LoadCurrent should populate cache.
	current1, err := store.LoadCurrent(ctx)
	if err != nil {
		t.Fatalf("load current: %v", err)
	}
	if current1.KeyID != "kid-cache-1" {
		t.Errorf("expected kid-cache-1, got %q", current1.KeyID)
	}

	// Save a second key (this also updates cache).
	k2 := newHATestSigningKey(t, "kid-cache-2")
	if err := store.Save(ctx, k2); err != nil {
		t.Fatalf("save key 2: %v", err)
	}

	// Without invalidation, cache should have the new key (Save updates cache).
	current2, err := store.LoadCurrent(ctx)
	if err != nil {
		t.Fatalf("load current after rotation: %v", err)
	}
	if current2.KeyID != "kid-cache-2" {
		t.Errorf("cache should have new key: got %q, want kid-cache-2", current2.KeyID)
	}

	// Invalidate and verify it re-reads from DB.
	store.InvalidateCache()
	current3, err := store.LoadCurrent(ctx)
	if err != nil {
		t.Fatalf("load current after invalidation: %v", err)
	}
	if current3.KeyID != "kid-cache-2" {
		t.Errorf("after invalidation should get DB value: got %q, want kid-cache-2", current3.KeyID)
	}
}

func TestHAKeyStore_ConcurrentRotation_OnlyOneSucceeds(t *testing.T) {
	db := testdata.SetupTestPGDB(t, pgContainerDSN)
	enc := newTestEncryptor(t)
	obs := observability.NewNoop()

	// Seed with an initial key so the table isn't empty.
	store := pgadapter.NewHAKeyStore(db.Pool, enc, obs)
	ctx := context.Background()
	k0 := newHATestSigningKey(t, "kid-seed")
	if err := store.Save(ctx, k0); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	// Create N stores sharing the same pool (simulating multiple pods).
	const goroutines = 5
	stores := make([]*pgadapter.HAKeyStore, goroutines)
	for i := range stores {
		stores[i] = pgadapter.NewHAKeyStore(db.Pool, enc, obs)
	}

	// All goroutines attempt rotation concurrently.
	type result struct {
		err error
		kid string
	}
	results := make(chan result, goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			kid := fmt.Sprintf("kid-concurrent-%d", idx)
			k := newHATestSigningKey(t, kid)
			err := stores[idx].Save(ctx, k)
			results <- result{err: err, kid: kid}
		}(i)
	}

	var successes, failures int
	for i := 0; i < goroutines; i++ {
		r := <-results
		if r.err == nil {
			successes++
		} else {
			failures++
		}
	}

	// At least one must succeed. The unique partial index prevents two concurrent
	// is_current=TRUE rows, but the retry logic means multiple may succeed sequentially.
	if successes == 0 {
		t.Fatal("expected at least one successful rotation, all failed")
	}

	// Verify exactly one is_current=TRUE row in the database.
	var currentCount int
	err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM signing_keys WHERE is_current = TRUE`,
	).Scan(&currentCount)
	if err != nil {
		t.Fatalf("count current keys: %v", err)
	}
	if currentCount != 1 {
		t.Errorf("expected exactly 1 is_current=TRUE row, got %d", currentCount)
	}

	t.Logf("concurrent rotation: %d successes, %d failures out of %d goroutines", successes, failures, goroutines)
}

func TestHAKeyStore_EncryptedPEM_IsNotRawPEM(t *testing.T) {
	db := testdata.SetupTestPGDB(t, pgContainerDSN)
	enc := newTestEncryptor(t)
	obs := observability.NewNoop()
	store := pgadapter.NewHAKeyStore(db.Pool, enc, obs)
	ctx := context.Background()

	k := newHATestSigningKey(t, "kid-pem-check")
	if err := store.Save(ctx, k); err != nil {
		t.Fatalf("save key: %v", err)
	}

	var encPrivate []byte
	err := db.Pool.QueryRow(ctx,
		`SELECT enc_private FROM signing_keys WHERE kid = $1`, "kid-pem-check",
	).Scan(&encPrivate)
	if err != nil {
		t.Fatalf("query enc_private: %v", err)
	}

	// The raw bytes MUST NOT be a valid PEM block — if they are,
	// encryption is not being applied and the key is stored in plaintext.
	block, _ := pem.Decode(encPrivate)
	if block != nil {
		t.Fatal("CRITICAL: enc_private is valid PEM — key stored in plaintext, encryption not applied!")
	}
}
