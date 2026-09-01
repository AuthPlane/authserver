package static_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/authplane/authserver/internal/adapters/aesmaster"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

func newTestAESMaster(t *testing.T) *aesmaster.Encryptor {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	enc, err := aesmaster.New(hex.EncodeToString(key), observability.NewNoop())
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func TestDataEncryptorFieldEncryptor_RoundTrip(t *testing.T) {
	fe := static.NewDataEncryptorFieldEncryptor(newTestAESMaster(t))
	owner := output.Owner{Kind: output.OwnerKindBrokerProvider, ID: "prov123"}
	ct, err := fe.Encrypt(context.Background(), []byte("s3cret"), owner)
	if err != nil {
		t.Fatalf("Encrypt: unexpected error: %v", err)
	}
	pt, err := fe.Decrypt(context.Background(), ct, owner)
	if err != nil {
		t.Fatalf("Decrypt: unexpected error: %v", err)
	}
	if string(pt) != "s3cret" {
		t.Fatalf("Decrypt: got %q, want %q", string(pt), "s3cret")
	}
}

func TestDataEncryptorFieldEncryptor_OwnerMismatchFails(t *testing.T) {
	fe := static.NewDataEncryptorFieldEncryptor(newTestAESMaster(t))
	ct, _ := fe.Encrypt(context.Background(), []byte("s3cret"),
		output.Owner{Kind: output.OwnerKindBrokerProvider, ID: "prov123"})
	_, err := fe.Decrypt(context.Background(), ct,
		output.Owner{Kind: output.OwnerKindBrokerProvider, ID: "OTHER"})
	if err == nil {
		t.Fatal("expected error when decrypting with different owner — ownerContext is GCM AAD")
	}
}

func TestDataEncryptorFieldEncryptor_DriverName(t *testing.T) {
	fe := static.NewDataEncryptorFieldEncryptor(newTestAESMaster(t))
	if fe.DriverName() != "aes_master" {
		t.Fatalf("DriverName: got %q, want %q", fe.DriverName(), "aes_master")
	}
}
