package encryption_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/adapters/encryption"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
)

// randomKeyHex returns a fresh 32-byte AES master key as 64 hex characters.
func randomKeyHex(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(key)
}

// aesConfig builds an aes_master DataEncryptionConfig reading its key from
// keyEnv (and, when non-empty, its rotation fallback from oldKeyEnv).
func aesConfig(keyEnv, oldKeyEnv string) config.DataEncryptionConfig {
	return config.DataEncryptionConfig{
		Driver: "aes_master",
		AESMaster: config.AESMasterConfig{
			KeyEnv:    keyEnv,
			OldKeyEnv: oldKeyEnv,
		},
	}
}

func TestOpen_AESMaster_RoundTrip(t *testing.T) {
	t.Setenv("AP_TEST_ENC_KEY", randomKeyHex(t))

	enc, err := encryption.Open(context.Background(), aesConfig("AP_TEST_ENC_KEY", ""), observability.NewNoop())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if enc.DriverName() != "aes_master" {
		t.Errorf("driver name = %q, want aes_master", enc.DriverName())
	}

	plaintext := []byte("refresh-token-secret")
	ct, err := enc.Encrypt(context.Background(), plaintext, "owner-1")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("ciphertext contains the plaintext verbatim")
	}

	got, err := enc.Decrypt(context.Background(), ct, "owner-1")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round trip = %q, want %q", got, plaintext)
	}
}

func TestOpen_AESMaster_WrongKeyFailsToDecrypt(t *testing.T) {
	t.Setenv("AP_TEST_ENC_KEY_A", randomKeyHex(t))
	t.Setenv("AP_TEST_ENC_KEY_B", randomKeyHex(t))

	encA, err := encryption.Open(context.Background(), aesConfig("AP_TEST_ENC_KEY_A", ""), observability.NewNoop())
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	encB, err := encryption.Open(context.Background(), aesConfig("AP_TEST_ENC_KEY_B", ""), observability.NewNoop())
	if err != nil {
		t.Fatalf("open B: %v", err)
	}

	ct, err := encA.Encrypt(context.Background(), []byte("secret"), "owner-1")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := encB.Decrypt(context.Background(), ct, "owner-1"); !errors.Is(err, domain.ErrDecryptionFailed) {
		t.Errorf("decrypt with the wrong key: err = %v, want ErrDecryptionFailed", err)
	}
}

func TestOpen_AESMaster_WrongOwnerContextFailsToDecrypt(t *testing.T) {
	t.Setenv("AP_TEST_ENC_KEY", randomKeyHex(t))

	enc, err := encryption.Open(context.Background(), aesConfig("AP_TEST_ENC_KEY", ""), observability.NewNoop())
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	ct, err := enc.Encrypt(context.Background(), []byte("secret"), "owner-1")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := enc.Decrypt(context.Background(), ct, "owner-2"); !errors.Is(err, domain.ErrDecryptionFailed) {
		t.Errorf("decrypt under another owner: err = %v, want ErrDecryptionFailed", err)
	}
}

func TestOpen_AESMaster_TamperedCiphertextRejected(t *testing.T) {
	t.Setenv("AP_TEST_ENC_KEY", randomKeyHex(t))

	enc, err := encryption.Open(context.Background(), aesConfig("AP_TEST_ENC_KEY", ""), observability.NewNoop())
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	ct, err := enc.Encrypt(context.Background(), []byte("secret"), "owner-1")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	cases := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"flipped byte in the GCM body", func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[len(out)-1] ^= 0x01
			return out
		}},
		{"flipped nonce byte", func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[1] ^= 0x01
			return out
		}},
		{"unknown version byte", func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[0] = 0x7f
			return out
		}},
		{"truncated below the minimum frame", func(b []byte) []byte {
			return b[:8]
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := enc.Decrypt(context.Background(), tc.mutate(ct), "owner-1")
			if !errors.Is(err, domain.ErrDecryptionFailed) {
				t.Errorf("err = %v, want ErrDecryptionFailed", err)
			}
		})
	}
}

// Key rotation: a value encrypted under the previous key must still decrypt
// when that key is supplied through old_key_env, and new writes must go out
// under the current key only.
func TestOpen_AESMaster_OldKeyFallbackDecrypts(t *testing.T) {
	oldKey := randomKeyHex(t)
	newKey := randomKeyHex(t)
	t.Setenv("AP_TEST_ENC_OLD", oldKey)
	t.Setenv("AP_TEST_ENC_NEW", newKey)

	before, err := encryption.Open(context.Background(), aesConfig("AP_TEST_ENC_OLD", ""), observability.NewNoop())
	if err != nil {
		t.Fatalf("open under old key: %v", err)
	}
	ct, err := before.Encrypt(context.Background(), []byte("pre-rotation"), "owner-1")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	rotated, err := encryption.Open(context.Background(), aesConfig("AP_TEST_ENC_NEW", "AP_TEST_ENC_OLD"), observability.NewNoop())
	if err != nil {
		t.Fatalf("open with rotation fallback: %v", err)
	}
	got, err := rotated.Decrypt(context.Background(), ct, "owner-1")
	if err != nil {
		t.Fatalf("decrypt via old-key fallback: %v", err)
	}
	if string(got) != "pre-rotation" {
		t.Errorf("plaintext = %q, want pre-rotation", got)
	}

	// New writes must not be readable by the old key alone.
	ct2, err := rotated.Encrypt(context.Background(), []byte("post-rotation"), "owner-1")
	if err != nil {
		t.Fatalf("encrypt after rotation: %v", err)
	}
	if _, err := before.Decrypt(context.Background(), ct2, "owner-1"); !errors.Is(err, domain.ErrDecryptionFailed) {
		t.Errorf("old-key-only encryptor read a post-rotation value: err = %v", err)
	}
}

// An old_key_env that names an unset variable is not an error: the fallback
// is simply not installed. An old_key_env that names a variable holding a
// malformed key is a configuration error.
func TestOpen_AESMaster_OldKeyEnvHandling(t *testing.T) {
	t.Setenv("AP_TEST_ENC_KEY", randomKeyHex(t))

	t.Run("unset old key env is ignored", func(t *testing.T) {
		if _, err := encryption.Open(context.Background(), aesConfig("AP_TEST_ENC_KEY", "AP_TEST_ENC_OLD_UNSET"), observability.NewNoop()); err != nil {
			t.Fatalf("open: %v", err)
		}
	})

	t.Run("malformed old key is refused", func(t *testing.T) {
		t.Setenv("AP_TEST_ENC_OLD_BAD", "not-hex")
		_, err := encryption.Open(context.Background(), aesConfig("AP_TEST_ENC_KEY", "AP_TEST_ENC_OLD_BAD"), observability.NewNoop())
		if err == nil || !strings.Contains(err.Error(), "old key") {
			t.Fatalf("err = %v, want an old-key error", err)
		}
	})
}

func TestOpen_AESMaster_RejectsBadKeys(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"unset env resolves to empty key", "", "exactly 32 bytes"},
		{"not hex", "zz", "not valid hex"},
		{"wrong length", "abcd", "exactly 32 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AP_TEST_ENC_BAD", tc.value)
			_, err := encryption.Open(context.Background(), aesConfig("AP_TEST_ENC_BAD", ""), observability.NewNoop())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestOpen_UnsupportedDriver(t *testing.T) {
	_, err := encryption.Open(context.Background(), config.DataEncryptionConfig{Driver: "kms_of_the_future"}, observability.NewNoop())
	if err == nil || !strings.Contains(err.Error(), `unsupported data_encryption.driver: "kms_of_the_future"`) {
		t.Fatalf("err = %v, want unsupported-driver error", err)
	}
	if _, err := encryption.Open(context.Background(), config.DataEncryptionConfig{}, observability.NewNoop()); err == nil {
		t.Fatal("empty driver: expected an error")
	}
}

// The Vault Transit driver performs no network I/O at construction with a
// static token, so the factory path is checkable without a Vault: a fully
// specified config yields an encryptor reporting its driver name, and the
// missing-address / missing-credential refusals from the client constructor
// surface through the factory's wrap.
func TestOpen_VaultTransit(t *testing.T) {
	t.Run("static token builds an encryptor without dialing", func(t *testing.T) {
		t.Setenv("AP_TEST_VAULT_TOKEN", "s.test-token")
		enc, err := encryption.Open(context.Background(), config.DataEncryptionConfig{
			Driver: "vault_transit_encrypt",
			VaultTransitEncrypt: config.VaultTransitEncryptConfig{
				Address:  "http://127.0.0.1:1",
				TokenEnv: "AP_TEST_VAULT_TOKEN",
				KeyName:  "authserver-data",
			},
		}, observability.NewNoop())
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if enc.DriverName() != "vault_transit_encrypt" {
			t.Errorf("driver name = %q, want vault_transit_encrypt", enc.DriverName())
		}
	})

	t.Run("missing address is refused", func(t *testing.T) {
		t.Setenv("AP_TEST_VAULT_TOKEN", "s.test-token")
		_, err := encryption.Open(context.Background(), config.DataEncryptionConfig{
			Driver: "vault_transit_encrypt",
			VaultTransitEncrypt: config.VaultTransitEncryptConfig{
				TokenEnv: "AP_TEST_VAULT_TOKEN",
				KeyName:  "authserver-data",
			},
		}, observability.NewNoop())
		if err == nil || !strings.Contains(err.Error(), "vault transit encrypt client") || !strings.Contains(err.Error(), "address") {
			t.Fatalf("err = %v, want a wrapped vault-address error", err)
		}
	})

	t.Run("missing token is refused", func(t *testing.T) {
		_, err := encryption.Open(context.Background(), config.DataEncryptionConfig{
			Driver: "vault_transit_encrypt",
			VaultTransitEncrypt: config.VaultTransitEncryptConfig{
				Address:  "http://127.0.0.1:1",
				TokenEnv: "AP_TEST_VAULT_TOKEN_UNSET",
				KeyName:  "authserver-data",
			},
		}, observability.NewNoop())
		if err == nil || !strings.Contains(err.Error(), "vault transit encrypt client") {
			t.Fatalf("err = %v, want a wrapped vault-client error", err)
		}
	})
}
