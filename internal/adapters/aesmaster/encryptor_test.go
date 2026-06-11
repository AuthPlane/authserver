package aesmaster

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
)

func testKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(key)
}

func newTestEncryptor(t *testing.T) *Encryptor {
	t.Helper()
	enc, err := New(testKey(t), observability.NewNoop())
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func TestAESMaster_EncryptDecrypt_RoundTrip(t *testing.T) {
	enc := newTestEncryptor(t)
	ctx := context.Background()

	tests := []struct {
		name         string
		plaintext    []byte
		ownerContext string
	}{
		{"simple text", []byte("hello world"), "connection:user1:github:conn1"},
		{"binary data", []byte{0x00, 0xFF, 0x01, 0xFE}, "signing-key:key1"},
		{"long data", make([]byte, 4096), "connection:user2:linear:conn2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := enc.Encrypt(ctx, tt.plaintext, tt.ownerContext)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			decrypted, err := enc.Decrypt(ctx, ciphertext, tt.ownerContext)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if len(decrypted) != len(tt.plaintext) {
				t.Fatalf("length mismatch: got %d, want %d", len(decrypted), len(tt.plaintext))
			}
			for i := range decrypted {
				if decrypted[i] != tt.plaintext[i] {
					t.Fatalf("byte %d mismatch: got %02x, want %02x", i, decrypted[i], tt.plaintext[i])
				}
			}
		})
	}
}

func TestAESMaster_DifferentOwnerContext_CannotDecrypt(t *testing.T) {
	enc := newTestEncryptor(t)
	ctx := context.Background()

	plaintext := []byte("sensitive token value")
	ciphertext, err := enc.Encrypt(ctx, plaintext, "connection:user1:github:abc")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = enc.Decrypt(ctx, ciphertext, "connection:user2:github:abc")
	if err == nil {
		t.Fatal("expected error when decrypting with different ownerContext")
	}
	if !errors.Is(err, domain.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestAESMaster_NoncesAreUnique(t *testing.T) {
	enc := newTestEncryptor(t)
	ctx := context.Background()

	plaintext := []byte("same plaintext every time")
	ownerContext := "connection:user1:github:conn1"
	const iterations = 10000

	seen := make(map[string]struct{}, iterations)
	for i := 0; i < iterations; i++ {
		ciphertext, err := enc.Encrypt(ctx, plaintext, ownerContext)
		if err != nil {
			t.Fatalf("Encrypt %d failed: %v", i, err)
		}

		// Nonce is at bytes [1:13] (after the version byte).
		nonce := string(ciphertext[1 : 1+nonceSize])
		if _, exists := seen[nonce]; exists {
			t.Fatalf("duplicate nonce at iteration %d", i)
		}
		seen[nonce] = struct{}{}
	}
}

func TestAESMaster_WrongMasterKey_CannotDecrypt(t *testing.T) {
	obs := observability.NewNoop()
	ctx := context.Background()

	enc1, err := New(testKey(t), obs)
	if err != nil {
		t.Fatal(err)
	}
	enc2, err := New(testKey(t), obs)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("secret data")
	ownerContext := "connection:user1:github:conn1"

	ciphertext, err := enc1.Encrypt(ctx, plaintext, ownerContext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = enc2.Decrypt(ctx, ciphertext, ownerContext)
	if err == nil {
		t.Fatal("expected error when decrypting with different master key")
	}
	if !errors.Is(err, domain.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestAESMaster_VersionByte_IsFirstByte(t *testing.T) {
	enc := newTestEncryptor(t)
	ctx := context.Background()

	ciphertext, err := enc.Encrypt(ctx, []byte("test"), "ctx")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if ciphertext[0] != 0x02 {
		t.Fatalf("first byte should be 0x02 (version V2), got 0x%02x", ciphertext[0])
	}
}

func TestAESMaster_EmptyPlaintext_RoundTrip(t *testing.T) {
	enc := newTestEncryptor(t)
	ctx := context.Background()

	ciphertext, err := enc.Encrypt(ctx, []byte{}, "connection:user1:github:conn1")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := enc.Decrypt(ctx, ciphertext, "connection:user1:github:conn1")
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}

func TestAESMaster_OldKeyFallback_DecryptsWithOldKey(t *testing.T) {
	obs := observability.NewNoop()
	ctx := context.Background()

	oldKeyHex := testKey(t)
	newKeyHex := testKey(t)

	// Encrypt with old key (no old key option — it's the primary key).
	oldEnc, err := New(oldKeyHex, obs)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("rotate-me-token")
	ownerContext := "connection:user1:github:conn1"
	ciphertext, err := oldEnc.Encrypt(ctx, plaintext, ownerContext)
	if err != nil {
		t.Fatalf("Encrypt with old key: %v", err)
	}

	// Create encryptor with NEW key + OLD key fallback.
	newEnc, err := New(newKeyHex, obs, WithOldKey(oldKeyHex))
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt should succeed using old key fallback.
	decrypted, err := newEnc.Decrypt(ctx, ciphertext, ownerContext)
	if err != nil {
		t.Fatalf("Decrypt with old key fallback: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestAESMaster_OldKeyFallback_NewKeyTakesPriority(t *testing.T) {
	obs := observability.NewNoop()
	ctx := context.Background()

	oldKeyHex := testKey(t)
	newKeyHex := testKey(t)

	// Create encryptor with NEW key + OLD key fallback.
	enc, err := New(newKeyHex, obs, WithOldKey(oldKeyHex))
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt with new encryptor (should use new key).
	plaintext := []byte("new-key-token")
	ownerContext := "connection:user1:github:conn1"
	ciphertext, err := enc.Encrypt(ctx, plaintext, ownerContext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Decrypt with new-key-only encryptor (no old key) should work.
	newOnlyEnc, err := New(newKeyHex, obs)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := newOnlyEnc.Decrypt(ctx, ciphertext, ownerContext)
	if err != nil {
		t.Fatalf("Decrypt with new key only: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestAESMaster_OldKeyFallback_BothKeysFail_ReturnsError(t *testing.T) {
	obs := observability.NewNoop()
	ctx := context.Background()

	key1 := testKey(t)
	key2 := testKey(t)
	key3 := testKey(t)

	// Encrypt with key1.
	enc1, err := New(key1, obs)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := enc1.Encrypt(ctx, []byte("secret"), "ctx")
	if err != nil {
		t.Fatal(err)
	}

	// Try to decrypt with key2 (new) + key3 (old) — neither is key1.
	enc23, err := New(key2, obs, WithOldKey(key3))
	if err != nil {
		t.Fatal(err)
	}
	_, err = enc23.Decrypt(ctx, ciphertext, "ctx")
	if !errors.Is(err, domain.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestAESMaster_OldKeyRemoved_CannotDecryptOldCiphertext(t *testing.T) {
	obs := observability.NewNoop()
	ctx := context.Background()

	oldKeyHex := testKey(t)
	newKeyHex := testKey(t)

	// Encrypt with old key.
	oldEnc, err := New(oldKeyHex, obs)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := oldEnc.Encrypt(ctx, []byte("old-secret"), "ctx")
	if err != nil {
		t.Fatal(err)
	}

	// New encryptor WITHOUT old key fallback — simulates old_key_env removed from config.
	newEnc, err := New(newKeyHex, obs)
	if err != nil {
		t.Fatal(err)
	}
	_, err = newEnc.Decrypt(ctx, ciphertext, "ctx")
	if !errors.Is(err, domain.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed after old key removed, got: %v", err)
	}
}

func TestAESMaster_BadKeyLength_ConstructionFails(t *testing.T) {
	obs := observability.NewNoop()

	tests := []struct {
		name   string
		keyHex string
	}{
		{"too short (31 bytes)", hex.EncodeToString(make([]byte, 31))},
		{"too long (33 bytes)", hex.EncodeToString(make([]byte, 33))},
		{"empty", ""},
		{"not hex", "not-valid-hex-string-at-all-this-is-garbage-text"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.keyHex, obs)
			if err == nil {
				t.Fatal("expected error for bad key length")
			}
		})
	}
}
