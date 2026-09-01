// Seam tests for the SecretEncoder wiring in BrokerProviderAdminService.
// These tests exercise the key paths:
//
//  1. A recording fake that returns the Ref unchanged — proves the verbatim
//     invariant holds when a SecretEncoder is wired and a reference is supplied.
//  2. A fake that returns a fixed ref for any input — proves the routing seam
//     (ref written back to <field>_ref) works correctly.
//  3. A fake that returns a ciphertext — proves the encrypted-column path
//     (EncSecretData/EncSecretBackend set, config_data stripped) works.
package services

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/adapters/aesmaster"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// newColumnPathEncoder builds a real ConfigSecretBackend backed by an aesmaster
// encryptor, so Encode of a raw value yields a ciphertext (the encrypted-column
// path) rather than rejecting it.
func newColumnPathEncoder(t *testing.T) *static.ConfigSecretBackend {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	enc, err := aesmaster.New(hex.EncodeToString(key), observability.NewNoop())
	if err != nil {
		t.Fatal(err)
	}
	return static.NewConfigSecretBackend(static.NewDataEncryptorFieldEncryptor(enc))
}

// TestSecretEncoder_ColumnPath_RawValueEncrypted wires a real encryptor-backed
// ConfigSecretBackend and asserts the encrypted-column path: a raw client_secret
// is encrypted into EncSecretData (with EncSecretBackend recorded) and config_data
// carries neither the raw value nor a client_secret_ref.
func TestSecretEncoder_ColumnPath_RawValueEncrypted(t *testing.T) {
	providers := newFakeBrokerProviderStore()
	svc := NewBrokerProviderAdminService(providers, observability.NewNoop(), nil, newColumnPathEncoder(t))

	p := &resource.BrokerProvider{
		Slug:        "col-path",
		DisplayName: "Column Path",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"x","client_secret":"ghp_raw_value"}`),
	}
	if err := svc.Create(t.Context(), p); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := svc.GetBySlug(t.Context(), "col-path")
	if err != nil {
		t.Fatalf("GetBySlug: %v", err)
	}
	if len(got.EncSecretData) == 0 {
		t.Fatal("expected EncSecretData to be populated")
	}
	if got.EncSecretBackend != "aes_master" {
		t.Errorf("EncSecretBackend = %q, want aes_master", got.EncSecretBackend)
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(got.ConfigData, &cfg); err != nil {
		t.Fatalf("unmarshal config_data: %v", err)
	}
	if _, ok := cfg["client_secret"]; ok {
		t.Error("raw client_secret must not remain in config_data")
	}
	if _, ok := cfg["client_secret_ref"]; ok {
		t.Error("client_secret_ref must not be present on the column path")
	}
}

// TestSecretEncoder_Patch_ColumnToRef_ClearsStaleCiphertext verifies that rotating a
// provider's secret from a raw (encrypted-column) value to a client_secret_ref drops
// the stale EncSecretData/EncSecretBackend. Without this, the Data→Ref read
// precedence would silently return the OLD secret at vend after the rotation.
func TestSecretEncoder_Patch_ColumnToRef_ClearsStaleCiphertext(t *testing.T) {
	providers := newFakeBrokerProviderStore()
	svc := NewBrokerProviderAdminService(providers, observability.NewNoop(), nil, newColumnPathEncoder(t))

	// Create with a raw secret → encrypted column populated.
	p := &resource.BrokerProvider{
		Slug:        "rotate-col-to-ref",
		DisplayName: "Rotate",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"x","client_secret":"ghp_raw_value"}`),
	}
	if err := svc.Create(t.Context(), p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	created, err := svc.GetBySlug(t.Context(), p.Slug)
	if err != nil {
		t.Fatalf("GetBySlug: %v", err)
	}
	if len(created.EncSecretData) == 0 {
		t.Fatal("precondition: expected EncSecretData populated after Create")
	}

	// Patch to a client_secret_ref → the stale ciphertext column must be cleared.
	patchCfg := json.RawMessage(`{"client_id":"x","client_secret_ref":"CONNECTOR_NEW_SECRET"}`)
	if _, perr := svc.Patch(t.Context(), created.ID, input.BrokerProviderPatch{ConfigData: &patchCfg}); perr != nil {
		t.Fatalf("Patch: %v", perr)
	}

	got, err := svc.GetBySlug(t.Context(), p.Slug)
	if err != nil {
		t.Fatalf("GetBySlug after patch: %v", err)
	}
	if len(got.EncSecretData) != 0 {
		t.Errorf("EncSecretData must be cleared after rotating to a ref, got %d bytes", len(got.EncSecretData))
	}
	if got.EncSecretBackend != "" {
		t.Errorf("EncSecretBackend must be cleared after rotating to a ref, got %q", got.EncSecretBackend)
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(got.ConfigData, &cfg); err != nil {
		t.Fatalf("unmarshal config_data: %v", err)
	}
	if _, ok := cfg["client_secret_ref"]; !ok {
		t.Error("expected client_secret_ref present after rotation to ref")
	}
}

// TestSecretEncoder_Patch_RefToColumn_PopulatesAndStripsRef verifies the symmetric
// rotation: patching a raw client_secret over a provider that previously used a
// client_secret_ref encrypts into the column AND strips the stale *_ref key.
func TestSecretEncoder_Patch_RefToColumn_PopulatesAndStripsRef(t *testing.T) {
	providers := newFakeBrokerProviderStore()
	svc := NewBrokerProviderAdminService(providers, observability.NewNoop(), nil, newColumnPathEncoder(t))

	// Seed with a client_secret_ref (env path) → no encrypted column.
	seed := &resource.BrokerProvider{
		Slug:        "rotate-ref-to-col",
		DisplayName: "Rotate",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"x","client_secret_ref":"OLD_REF"}`),
	}
	if err := svc.Create(t.Context(), seed); err != nil {
		t.Fatalf("Create: %v", err)
	}
	created, err := svc.GetBySlug(t.Context(), seed.Slug)
	if err != nil {
		t.Fatalf("GetBySlug: %v", err)
	}
	if len(created.EncSecretData) != 0 {
		t.Fatal("precondition: ref-path provider must have no EncSecretData")
	}

	// Patch with a raw client_secret → encrypted column populates, stale ref stripped.
	patchCfg := json.RawMessage(`{"client_id":"x","client_secret":"ghp_raw_value"}`)
	if _, perr := svc.Patch(t.Context(), created.ID, input.BrokerProviderPatch{ConfigData: &patchCfg}); perr != nil {
		t.Fatalf("Patch: %v", perr)
	}

	got, err := svc.GetBySlug(t.Context(), seed.Slug)
	if err != nil {
		t.Fatalf("GetBySlug after patch: %v", err)
	}
	if len(got.EncSecretData) == 0 {
		t.Error("expected EncSecretData populated after rotating a raw value into the column")
	}
	if got.EncSecretBackend != "aes_master" {
		t.Errorf("EncSecretBackend = %q, want aes_master", got.EncSecretBackend)
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(got.ConfigData, &cfg); err != nil {
		t.Fatalf("unmarshal config_data: %v", err)
	}
	if _, ok := cfg["client_secret"]; ok {
		t.Error("raw client_secret must not remain in config_data")
	}
	if _, ok := cfg["client_secret_ref"]; ok {
		t.Error("stale client_secret_ref must be stripped after rotating to the column")
	}
}

// recordingSecretEncoder records calls and returns the Ref unchanged (env-backend
// passthrough behavior).
type recordingSecretEncoder struct {
	calls []output.SecretInput
}

func (r *recordingSecretEncoder) Encode(_ context.Context, in output.SecretInput) (output.EncodedSecret, error) {
	r.calls = append(r.calls, in)
	return output.EncodedSecret{Ref: in.Ref}, nil // passthrough: ref unchanged
}

// noopSecretEncoder models the env backend: it expects a Ref (returns it
// unchanged, so config_data stays verbatim) and rejects a raw Value with
// output.ErrSecretInputRejected. Default encoder for tests that supply a
// reference rather than a raw value.
type noopSecretEncoder struct{}

func (noopSecretEncoder) Encode(_ context.Context, in output.SecretInput) (output.EncodedSecret, error) {
	if in.Value != "" {
		return output.EncodedSecret{}, fmt.Errorf("%w: env-like fake stores no inline values", output.ErrSecretInputRejected)
	}
	return output.EncodedSecret{Ref: in.Ref}, nil
}

// failingSecretEncoder always returns an error, to verify the error propagates
// and aborts Create/Patch before the provider is persisted.
type failingSecretEncoder struct{ err error }

func (f failingSecretEncoder) Encode(_ context.Context, _ output.SecretInput) (output.EncodedSecret, error) {
	return output.EncodedSecret{}, f.err
}

// rewritingSecretEncoder always returns a fixed ref regardless of input — it
// models recording a secret and assigning it a stable reference.
type rewritingSecretEncoder struct {
	fixedRef string
	calls    []output.SecretInput
}

func (r *rewritingSecretEncoder) Encode(_ context.Context, in output.SecretInput) (output.EncodedSecret, error) {
	r.calls = append(r.calls, in)
	return output.EncodedSecret{Ref: r.fixedRef}, nil
}

// TestSecretEncoder_RecordingFake_ConfigDataUnchanged wires the recording fake
// (returns Ref unchanged) and asserts:
//   - Encode is called exactly once with the expected Ref and Field.
//   - The persisted config_data is byte-identical to what was supplied.
func TestSecretEncoder_RecordingFake_ConfigDataUnchanged(t *testing.T) {
	providers := newFakeBrokerProviderStore()
	enc := &recordingSecretEncoder{}
	svc := NewBrokerProviderAdminService(
		providers,
		observability.NewNoop(),
		nil, // no audit
		enc,
		// tx = nil: use the direct (non-tx) path
	)

	in := []byte(`{"client_id":"gh-app","client_secret_ref":"CONNECTOR_X"}`)
	p := &resource.BrokerProvider{
		Slug:        "github-seam",
		DisplayName: "GitHub Seam",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  in,
	}

	if err := svc.Create(t.Context(), p); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Encode called exactly once.
	if len(enc.calls) != 1 {
		t.Fatalf("expected 1 Encode call, got %d", len(enc.calls))
	}
	call := enc.calls[0]
	if call.Ref != "CONNECTOR_X" {
		t.Errorf("Encode.Ref = %q, want %q", call.Ref, "CONNECTOR_X")
	}
	if call.Owner.Kind != output.OwnerKindBrokerProvider || call.Owner.ID != p.ID {
		t.Errorf("Encode.Owner = %+v, want broker-provider/%s", call.Owner, p.ID)
	}
	if call.Field != "client_secret" {
		t.Errorf("Encode.Field = %q, want %q", call.Field, "client_secret")
	}

	// config_data persisted verbatim (Ref unchanged → no re-marshal).
	got, err := svc.GetBySlug(t.Context(), p.Slug)
	if err != nil {
		t.Fatalf("GetBySlug: %v", err)
	}
	if !bytes.Equal(got.ConfigData, in) {
		t.Errorf("config_data not verbatim:\n  got  %s\n  want %s", got.ConfigData, in)
	}
}

// TestSecretEncoder_BothValueAndRef_Rejected: supplying both a literal
// client_secret and a client_secret_ref for the same field is ambiguous and must
// be rejected before Encode (symmetric with the OIDC config validation), so the
// literal is never silently encrypted and the provider is not persisted.
func TestSecretEncoder_BothValueAndRef_Rejected(t *testing.T) {
	providers := newFakeBrokerProviderStore()
	enc := &recordingSecretEncoder{}
	svc := NewBrokerProviderAdminService(
		providers,
		observability.NewNoop(),
		nil, // no audit
		enc,
	)

	p := &resource.BrokerProvider{
		Slug:        "github-both",
		DisplayName: "GitHub Both",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"gh","client_secret":"literal","client_secret_ref":"CONNECTOR_X"}`),
	}

	err := svc.Create(t.Context(), p)
	if err == nil {
		t.Fatal("expected Create to reject both client_secret and client_secret_ref set, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should state the fields are mutually exclusive: %v", err)
	}
	// Rejected before Encode — the literal must never reach the encoder.
	if len(enc.calls) != 0 {
		t.Errorf("Encode must not be called when the input is rejected, got %d call(s)", len(enc.calls))
	}
}

// TestSecretEncoder_Patch_RecordingFake_ConfigDataUnchanged wires the recording
// fake (returns Ref unchanged) on a Patch call that supplies new config_data
// and asserts:
//   - Encode is called exactly once with the expected inputs.
//   - The persisted config_data is byte-identical to what was patched in.
func TestSecretEncoder_Patch_RecordingFake_ConfigDataUnchanged(t *testing.T) {
	providers := newFakeBrokerProviderStore()
	enc := &recordingSecretEncoder{}
	svc := NewBrokerProviderAdminService(
		providers,
		observability.NewNoop(),
		nil, // no audit
		enc,
	)

	// Seed with the env-like encoder so the seed config_data is verbatim.
	seed := &resource.BrokerProvider{
		Slug:        "patch-seam",
		DisplayName: "Patch Seam",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"old"}`),
	}
	seedSvc := NewBrokerProviderAdminService(providers, observability.NewNoop(), nil, noopSecretEncoder{})
	if err := seedSvc.Create(t.Context(), seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	patchCfg := json.RawMessage(`{"client_id":"new","client_secret_ref":"PATCH_REF"}`)
	_, err := svc.Patch(t.Context(), seed.ID, input.BrokerProviderPatch{ConfigData: &patchCfg})
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}

	// Encode called exactly once for the ref field.
	if len(enc.calls) != 1 {
		t.Fatalf("expected 1 Encode call, got %d", len(enc.calls))
	}
	call := enc.calls[0]
	if call.Ref != "PATCH_REF" {
		t.Errorf("Encode.Ref = %q, want %q", call.Ref, "PATCH_REF")
	}
	if call.Owner.ID != seed.ID {
		t.Errorf("Encode.Owner.ID = %q, want %q", call.Owner.ID, seed.ID)
	}
	if call.Field != "client_secret" {
		t.Errorf("Encode.Field = %q, want %q", call.Field, "client_secret")
	}

	// config_data persisted verbatim (Ref unchanged → no re-marshal).
	got, err := svc.GetBySlug(t.Context(), seed.Slug)
	if err != nil {
		t.Fatalf("GetBySlug: %v", err)
	}
	if !bytes.Equal(got.ConfigData, patchCfg) {
		t.Errorf("config_data not verbatim:\n  got  %s\n  want %s", got.ConfigData, patchCfg)
	}
}

// TestSecretEncoder_Patch_RewritingFake_RefReplaced wires the rewriting fake
// (returns "sec_patch_id") on a Patch call that supplies new config_data and
// asserts the persisted client_secret_ref is replaced.
func TestSecretEncoder_Patch_RewritingFake_RefReplaced(t *testing.T) {
	providers := newFakeBrokerProviderStore()
	enc := &rewritingSecretEncoder{fixedRef: "sec_patch_id"}
	svc := NewBrokerProviderAdminService(
		providers,
		observability.NewNoop(),
		nil,
		enc,
	)

	seed := &resource.BrokerProvider{
		Slug:        "patch-rewrite",
		DisplayName: "Patch Rewrite",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"old"}`),
	}
	seedSvc := NewBrokerProviderAdminService(providers, observability.NewNoop(), nil, noopSecretEncoder{})
	if err := seedSvc.Create(t.Context(), seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	patchCfg := json.RawMessage(`{"client_id":"new","client_secret_ref":"ORIGINAL_REF"}`)
	_, err := svc.Patch(t.Context(), seed.ID, input.BrokerProviderPatch{ConfigData: &patchCfg})
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}

	got, err := svc.GetBySlug(t.Context(), seed.Slug)
	if err != nil {
		t.Fatalf("GetBySlug: %v", err)
	}
	var configMap map[string]json.RawMessage
	if err := json.Unmarshal(got.ConfigData, &configMap); err != nil {
		t.Fatalf("unmarshal config_data: %v", err)
	}
	var storedRef string
	if err := json.Unmarshal(configMap["client_secret_ref"], &storedRef); err != nil {
		t.Fatalf("unmarshal client_secret_ref: %v", err)
	}
	if storedRef != "sec_patch_id" {
		t.Errorf("client_secret_ref = %q, want %q", storedRef, "sec_patch_id")
	}
}

// TestSecretEncoder_RewritingFake_RefReplaced wires the rewriting fake (returns
// "sec_id" for every input) and asserts:
//   - Encode is called exactly once.
//   - The persisted config_data's client_secret_ref becomes "sec_id".
//   - Other fields in config_data are unaffected.
func TestSecretEncoder_RewritingFake_RefReplaced(t *testing.T) {
	providers := newFakeBrokerProviderStore()
	enc := &rewritingSecretEncoder{fixedRef: "sec_id"}
	svc := NewBrokerProviderAdminService(
		providers,
		observability.NewNoop(),
		nil, // no audit
		enc,
		// tx = nil: use the direct (non-tx) path
	)

	p := &resource.BrokerProvider{
		Slug:        "github-stored",
		DisplayName: "GitHub Stored",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"gh-app","client_secret_ref":"CONNECTOR_X"}`),
	}

	if err := svc.Create(t.Context(), p); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Encode called exactly once.
	if len(enc.calls) != 1 {
		t.Fatalf("expected 1 Encode call, got %d", len(enc.calls))
	}

	// config_data reflects the rewritten ref.
	got, err := svc.GetBySlug(t.Context(), p.Slug)
	if err != nil {
		t.Fatalf("GetBySlug: %v", err)
	}

	var configMap map[string]json.RawMessage
	if err := json.Unmarshal(got.ConfigData, &configMap); err != nil {
		t.Fatalf("unmarshal persisted config_data: %v", err)
	}

	var storedRef string
	if err := json.Unmarshal(configMap["client_secret_ref"], &storedRef); err != nil {
		t.Fatalf("unmarshal client_secret_ref: %v", err)
	}
	if storedRef != "sec_id" {
		t.Errorf("client_secret_ref = %q, want %q", storedRef, "sec_id")
	}

	// Other fields untouched.
	var clientID string
	if err := json.Unmarshal(configMap["client_id"], &clientID); err != nil {
		t.Fatalf("unmarshal client_id: %v", err)
	}
	if clientID != "gh-app" {
		t.Errorf("client_id = %q, want %q", clientID, "gh-app")
	}
}

// TestSecretEncoder_EncodeError_AbortsCreate verifies an Encode error propagates
// out of Create and the provider is NOT persisted (the Encode call runs before
// providers.Create inside the transaction).
func TestSecretEncoder_EncodeError_AbortsCreate(t *testing.T) {
	providers := newFakeBrokerProviderStore()
	wantErr := errors.New("secret backend unavailable")
	svc := NewBrokerProviderAdminService(
		providers, observability.NewNoop(), nil, failingSecretEncoder{err: wantErr})

	p := &resource.BrokerProvider{
		Slug:        "fail-create",
		DisplayName: "Fail Create",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"x","client_secret_ref":"CONNECTOR_X"}`),
	}
	err := svc.Create(t.Context(), p)
	if err == nil || !strings.Contains(err.Error(), "secret backend unavailable") {
		t.Fatalf("expected Encode error to propagate from Create, got: %v", err)
	}
	if _, gerr := svc.GetBySlug(t.Context(), "fail-create"); gerr == nil {
		t.Error("provider must NOT be persisted after an Encode error in Create")
	}
}

// TestSecretEncoder_EncodeError_AbortsPatch verifies an Encode error propagates
// out of Patch (when config_data is supplied) rather than persisting the update.
func TestSecretEncoder_EncodeError_AbortsPatch(t *testing.T) {
	providers := newFakeBrokerProviderStore()
	seed := &resource.BrokerProvider{
		Slug:        "fail-patch",
		DisplayName: "Fail Patch",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"old"}`),
	}
	seedSvc := NewBrokerProviderAdminService(providers, observability.NewNoop(), nil, noopSecretEncoder{})
	if err := seedSvc.Create(t.Context(), seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	wantErr := errors.New("secret backend unavailable")
	svc := NewBrokerProviderAdminService(
		providers, observability.NewNoop(), nil, failingSecretEncoder{err: wantErr})

	patchCfg := json.RawMessage(`{"client_id":"new","client_secret_ref":"CONNECTOR_X"}`)
	_, err := svc.Patch(t.Context(), seed.ID, input.BrokerProviderPatch{ConfigData: &patchCfg})
	if err == nil || !strings.Contains(err.Error(), "secret backend unavailable") {
		t.Fatalf("expected Encode error to propagate from Patch, got: %v", err)
	}
}

// TestSecretEncoder_RawValue_IngestedAndStripped verifies the raw-value ref path:
// a raw value in a routed secret field is forwarded to Encode, the returned ref is
// written to <field>_ref, and the raw <field> key is stripped from the persisted
// config_data.
func TestSecretEncoder_RawValue_IngestedAndStripped(t *testing.T) {
	providers := newFakeBrokerProviderStore()
	enc := &rewritingSecretEncoder{fixedRef: "sec_ingested"}
	svc := NewBrokerProviderAdminService(providers, observability.NewNoop(), nil, enc)

	p := &resource.BrokerProvider{
		Slug:        "raw-ingest",
		DisplayName: "Raw Ingest",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"x","client_secret":"ghp_raw_value"}`),
	}
	if err := svc.Create(t.Context(), p); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Encode received the raw Value (not a Ref).
	if len(enc.calls) != 1 {
		t.Fatalf("expected 1 Encode call, got %d", len(enc.calls))
	}
	if enc.calls[0].Value != "ghp_raw_value" || enc.calls[0].Ref != "" {
		t.Errorf("Encode input = %+v, want Value=ghp_raw_value Ref=\"\"", enc.calls[0])
	}

	got, err := svc.GetBySlug(t.Context(), "raw-ingest")
	if err != nil {
		t.Fatalf("GetBySlug: %v", err)
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(got.ConfigData, &cfg); err != nil {
		t.Fatalf("unmarshal config_data: %v", err)
	}
	if _, ok := cfg["client_secret"]; ok {
		t.Error("raw client_secret must be stripped from persisted config_data")
	}
	var ref string
	if err := json.Unmarshal(cfg["client_secret_ref"], &ref); err != nil {
		t.Fatalf("unmarshal client_secret_ref: %v", err)
	}
	if ref != "sec_ingested" {
		t.Errorf("client_secret_ref = %q, want sec_ingested", ref)
	}
}

// TestSecretEncoder_RejectedInput_Maps400 verifies that a rejected input
// (output.ErrSecretInputRejected — e.g. the env backend given a raw value)
// surfaces from Create as a 400 invalid_request, not a 500.
func TestSecretEncoder_RejectedInput_Maps400(t *testing.T) {
	providers := newFakeBrokerProviderStore()
	svc := NewBrokerProviderAdminService(providers, observability.NewNoop(), nil, noopSecretEncoder{})

	p := &resource.BrokerProvider{
		Slug:        "reject-400",
		DisplayName: "Reject",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"x","client_secret":"raw"}`),
	}
	err := svc.Create(t.Context(), p)
	if err == nil {
		t.Fatal("expected rejection, got nil")
	}
	domErr, ok := err.(domain.Error)
	if !ok || domErr.Code() != "invalid_request" {
		t.Errorf("expected invalid_request (400), got %T %v", err, err)
	}
}

// TestSecretEncoder_MalformedSecretRefType_Maps400 pins that a secret ref of the
// wrong JSON type (number, bool, …) is rejected at Create with a 400 rather than
// silently treated as absent (which would only surface as "ref is empty" at vend).
func TestSecretEncoder_MalformedSecretRefType_Maps400(t *testing.T) {
	providers := newFakeBrokerProviderStore()
	svc := NewBrokerProviderAdminService(providers, observability.NewNoop(), nil, noopSecretEncoder{})

	p := &resource.BrokerProvider{
		Slug:        "malformed-ref",
		DisplayName: "Malformed",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"x","client_secret_ref":123}`),
	}
	err := svc.Create(t.Context(), p)
	if err == nil {
		t.Fatal("expected rejection of non-string client_secret_ref, got nil")
	}
	domErr, ok := err.(domain.Error)
	if !ok || domErr.Code() != "invalid_request" {
		t.Errorf("expected invalid_request (400), got %T %v", err, err)
	}
	if len(providers.byID) != 0 {
		t.Errorf("provider must not be persisted on malformed ref, got %d", len(providers.byID))
	}
}

// TestSecretEncoder_NullSecretRef_TreatedAsAbsent pins that an explicit JSON null
// secret ref is treated as "not provided" (provider accepted, as with an omitted
// key), not as malformed input.
func TestSecretEncoder_NullSecretRef_TreatedAsAbsent(t *testing.T) {
	providers := newFakeBrokerProviderStore()
	svc := NewBrokerProviderAdminService(providers, observability.NewNoop(), nil, noopSecretEncoder{})

	p := &resource.BrokerProvider{
		Slug:        "null-ref",
		DisplayName: "Null",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"x","client_secret_ref":null}`),
	}
	if err := svc.Create(t.Context(), p); err != nil {
		t.Fatalf("explicit null ref should be accepted as absent, got: %v", err)
	}
}

// TestSecretEncoder_ServiceAccount_RoutesSAKeyRef proves the seam handles the
// service_account protocol's sa_key_ref the same way it handles oauth's
// client_secret_ref: routeSecretFields routes the field through the SecretEncoder
// (Field="sa_key", the operator's ref forwarded) and, for a passthrough backend,
// leaves config_data verbatim. Closes the write-side coverage gap (all other seam
// tests use ProtocolOAuth).
func TestSecretEncoder_ServiceAccount_RoutesSAKeyRef(t *testing.T) {
	providers := newFakeBrokerProviderStore()
	enc := &recordingSecretEncoder{}
	svc := NewBrokerProviderAdminService(providers, observability.NewNoop(), nil, enc)

	cfg := `{"token_url":"https://oauth2.googleapis.com/token","sa_email":"svc@p.iam.gserviceaccount.com","sa_key_ref":"AUTHPLANE_VAULT_GCP_SA_KEY"}`
	p := &resource.BrokerProvider{
		Slug:        "gcp-sa",
		DisplayName: "GCP SA",
		Protocol:    resource.ProtocolServiceAccount,
		ConfigData:  []byte(cfg),
	}
	if err := svc.Create(t.Context(), p); err != nil {
		t.Fatalf("create service_account provider: %v", err)
	}
	if len(enc.calls) != 1 {
		t.Fatalf("SecretEncoder.Encode calls = %d, want 1", len(enc.calls))
	}
	in := enc.calls[0]
	if in.Field != "sa_key" {
		t.Errorf("routed Field = %q, want %q", in.Field, "sa_key")
	}
	if in.Ref != "AUTHPLANE_VAULT_GCP_SA_KEY" {
		t.Errorf("routed Ref = %q, want the operator sa_key_ref", in.Ref)
	}
	if in.Owner.ID != p.ID {
		t.Errorf("routed Owner.ID = %q, want %q", in.Owner.ID, p.ID)
	}
	// Passthrough backend returns the ref unchanged → config_data must be verbatim.
	if string(p.ConfigData) != cfg {
		t.Errorf("config_data mutated on passthrough:\n got %s\nwant %s", p.ConfigData, cfg)
	}
}
