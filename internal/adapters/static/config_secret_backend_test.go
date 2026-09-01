package static_test

import (
	"context"
	"errors"
	"testing"

	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/output"
)

// Encode: raw Value + encryptor → Data + Backend set, no Ref.
func TestConfigSecretBackend_Encode_RawValue_Encrypts(t *testing.T) {
	b := static.NewConfigSecretBackend(static.NewDataEncryptorFieldEncryptor(newTestAESMaster(t)))
	enc, err := b.Encode(context.Background(), output.GetSecretInputForBrokerProvider(&resource.BrokerProvider{ID: "prov1"}, "s3cret", "", "client_secret"))
	if err != nil {
		t.Fatalf("Encode: unexpected error: %v", err)
	}
	if len(enc.Data) == 0 {
		t.Fatal("expected Data to be populated")
	}
	if enc.Backend != "aes_master" {
		t.Errorf("Backend = %q, want aes_master", enc.Backend)
	}
	if enc.Ref != "" {
		t.Errorf("Ref = %q, want empty on the ciphertext path", enc.Ref)
	}
}

// Encode: raw Value + NIL encryptor on the STRICT backend → ErrSecretInputRejected.
// The policy is a property of the wired backend (NewConfigSecretBackend = strict),
// not of the input, so the owner is irrelevant — a caller cannot opt into inline.
func TestConfigSecretBackend_Encode_RawValue_NoEncryptor_StrictRejected(t *testing.T) {
	b := static.NewConfigSecretBackend(nil)
	_, err := b.Encode(context.Background(), output.GetSecretInputForBrokerProvider(&resource.BrokerProvider{ID: "prov1"}, "s3cret", "", "client_secret"))
	if err == nil {
		t.Fatal("expected rejection for a raw value with no encryptor, got nil")
	}
	if !errors.Is(err, output.ErrSecretInputRejected) {
		t.Errorf("error should wrap ErrSecretInputRejected, got: %v", err)
	}
}

// Encode: raw Value + NIL encryptor on the INLINE backend → carried as-is
// plaintext in Data, NOT rejected. The inline tolerance comes from the wired
// backend (NewConfigSecretBackendInline), so the strict backend above and this
// one differ only by construction — a broker (strict) caller cannot opt in.
func TestConfigSecretBackend_Encode_RawValue_NoEncryptor_InlineCarried(t *testing.T) {
	b := static.NewConfigSecretBackendInline()
	got, err := b.Encode(context.Background(), output.GetSecretInputForBrokerProvider(&resource.BrokerProvider{ID: "prov1"}, "s3cret", "", "client_secret"))
	if err != nil {
		t.Fatalf("inline backend should not reject a raw value, got: %v", err)
	}
	if string(got.Data) != "s3cret" {
		t.Errorf("Data = %q, want s3cret (carried as-is)", string(got.Data))
	}
	if got.Backend != "" || got.Ref != "" {
		t.Errorf("inline-no-encryptor should set neither Backend nor Ref, got %+v", got)
	}
}

// Encode: Ref only → EncodedSecret{Ref: ...}, no Data.
func TestConfigSecretBackend_Encode_Ref_Passthrough(t *testing.T) {
	b := static.NewConfigSecretBackend(nil)
	enc, err := b.Encode(context.Background(), output.GetSecretInputForBrokerProvider(&resource.BrokerProvider{ID: "prov1"}, "", "CONNECTOR_X", "client_secret"))
	if err != nil {
		t.Fatalf("Encode: unexpected error: %v", err)
	}
	if enc.Ref != "CONNECTOR_X" {
		t.Errorf("Ref = %q, want CONNECTOR_X", enc.Ref)
	}
	if len(enc.Data) != 0 {
		t.Error("expected no Data on the ref path")
	}
}

// Resolve: Data set → decrypts to plaintext.
func TestConfigSecretBackend_Resolve_Data_Decrypts(t *testing.T) {
	b := static.NewConfigSecretBackend(static.NewDataEncryptorFieldEncryptor(newTestAESMaster(t)))
	enc, err := b.Encode(context.Background(), output.GetSecretInputForBrokerProvider(&resource.BrokerProvider{ID: "prov1"}, "s3cret", "", "client_secret"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := b.Resolve(context.Background(), output.GetSecretSourceForBrokerProvider(&resource.BrokerProvider{ID: "prov1", EncSecretData: enc.Data, EncSecretBackend: enc.Backend}, ""))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "s3cret" {
		t.Errorf("Resolve = %q, want s3cret", got)
	}
}

// Resolve: Data empty, Ref set → env lookup.
func TestConfigSecretBackend_Resolve_Ref_EnvLookup(t *testing.T) {
	t.Setenv("CONNECTOR_X", "env-value")
	b := static.NewConfigSecretBackend(nil)
	got, err := b.Resolve(context.Background(), output.SecretSource{Ref: "CONNECTOR_X"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "env-value" {
		t.Errorf("Resolve = %q, want env-value", got)
	}
}

// Resolve: Data set + NIL encryptor on the INLINE backend → returns string(Data)
// as-is. With no encryptor the inline backend treats Data as already-plaintext
// (the OIDC OSS inline-secret path).
func TestConfigSecretBackend_Resolve_Data_NoEncryptor_InlineReturnsAsIs(t *testing.T) {
	b := static.NewConfigSecretBackendInline()
	got, err := b.Resolve(context.Background(), output.GetSecretSourceForBrokerProvider(&resource.BrokerProvider{ID: "prov1", EncSecretData: []byte("inline-plaintext"), EncSecretBackend: ""}, ""))
	if err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}
	if got != "inline-plaintext" {
		t.Errorf("Resolve = %q, want inline-plaintext", got)
	}
}

// Resolve: Data set + NIL encryptor on the STRICT backend → FAILS CLOSED with
// ErrSecretUnresolvable. This is the safety property the two-backend split buys:
// an encrypted column read by a process with no decryptor can never surface its
// raw bytes as the secret (the broker never stores plaintext, so any Data here
// is ciphertext that must be decrypted or refused).
func TestConfigSecretBackend_Resolve_Data_NoEncryptor_StrictFailsClosed(t *testing.T) {
	b := static.NewConfigSecretBackend(nil)
	_, err := b.Resolve(context.Background(), output.GetSecretSourceForBrokerProvider(&resource.BrokerProvider{ID: "prov1", EncSecretData: []byte("ciphertext-bytes"), EncSecretBackend: ""}, ""))
	if err == nil {
		t.Fatal("expected fail-closed error for at-rest data with no decryptor, got nil")
	}
	if !errors.Is(err, output.ErrSecretUnresolvable) {
		t.Errorf("error should wrap ErrSecretUnresolvable, got: %v", err)
	}
}
