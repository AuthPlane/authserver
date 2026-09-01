package services

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

type brokerProviderAdminTestEnv struct {
	svc       *BrokerProviderAdminService
	providers *fakeBrokerProviderStore
	audit     *mockAuditRecorder
}

func newBrokerProviderAdminTestEnv() *brokerProviderAdminTestEnv {
	providers := newFakeBrokerProviderStore()
	auditMock := &mockAuditRecorder{}
	svc := NewBrokerProviderAdminService(providers, observability.NewNoop(), auditMock, noopSecretEncoder{})
	return &brokerProviderAdminTestEnv{svc: svc, providers: providers, audit: auditMock}
}

func TestBrokerProviderAdmin_Create_HappyPath(t *testing.T) {
	env := newBrokerProviderAdminTestEnv()
	ctx := context.Background()

	p := &resource.BrokerProvider{
		Slug:        "github",
		DisplayName: "GitHub",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"x"}`),
	}
	if err := env.svc.Create(ctx, p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if p.ID == "" {
		t.Fatal("expected ID to be assigned")
	}
	got, err := env.svc.GetByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Slug != "github" {
		t.Errorf("slug: got %q, want %q", got.Slug, "github")
	}
}

func TestBrokerProviderAdmin_Create_RejectsCallerSuppliedID(t *testing.T) {
	env := newBrokerProviderAdminTestEnv()
	p := &resource.BrokerProvider{
		ID:          "caller-supplied",
		Slug:        "x",
		DisplayName: "X",
		Protocol:    resource.ProtocolOAuth,
	}
	err := env.svc.Create(context.Background(), p)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	domErr, ok := err.(domain.Error)
	if !ok || domErr.Code() != "invalid_request" {
		t.Errorf("expected invalid_request, got %v", err)
	}
}

func TestBrokerProviderAdmin_Create_RejectsInvalidSlug(t *testing.T) {
	env := newBrokerProviderAdminTestEnv()
	p := &resource.BrokerProvider{
		Slug:        "Invalid Slug!",
		DisplayName: "X",
		Protocol:    resource.ProtocolOAuth,
	}
	err := env.svc.Create(context.Background(), p)
	if !errors.Is(err, domain.ErrInvalidSlug) {
		t.Fatalf("expected ErrInvalidSlug, got %v", err)
	}
}

func TestBrokerProviderAdmin_Create_RejectsUnknownProtocol(t *testing.T) {
	env := newBrokerProviderAdminTestEnv()
	p := &resource.BrokerProvider{
		Slug:        "x",
		DisplayName: "X",
		Protocol:    "invented-protocol",
	}
	err := env.svc.Create(context.Background(), p)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	domErr, ok := err.(domain.Error)
	if !ok || domErr.Code() != "invalid_request" {
		t.Errorf("expected invalid_request, got %v", err)
	}
}

func TestBrokerProviderAdmin_Patch_AppliesOnlySuppliedFields(t *testing.T) {
	env := newBrokerProviderAdminTestEnv()
	ctx := context.Background()

	p := &resource.BrokerProvider{
		Slug:        "guarded",
		DisplayName: "Guarded",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"original":"data"}`),
	}
	if err := env.svc.Create(ctx, p); err != nil {
		t.Fatalf("seed: %v", err)
	}

	newDisplay := "Renamed"
	got, err := env.svc.Patch(ctx, p.ID, input.BrokerProviderPatch{DisplayName: &newDisplay})
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if got.DisplayName != newDisplay {
		t.Errorf("display_name: got %q, want %q", got.DisplayName, newDisplay)
	}
	if string(got.ConfigData) != `{"original":"data"}` {
		t.Errorf("config_data should be unchanged, got %s", string(got.ConfigData))
	}
	if got.Protocol != resource.ProtocolOAuth {
		t.Errorf("protocol changed unexpectedly: got %q", got.Protocol)
	}
}

func TestBrokerProviderAdmin_Patch_ConfigDataPassthrough(t *testing.T) {
	env := newBrokerProviderAdminTestEnv()
	ctx := context.Background()

	p := &resource.BrokerProvider{
		Slug:        "passthrough",
		DisplayName: "Pass",
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{}`),
	}
	if err := env.svc.Create(ctx, p); err != nil {
		t.Fatalf("seed: %v", err)
	}

	newCfg := json.RawMessage(`{"weird":"shape","with":["nested",{"objects":true}]}`)
	got, err := env.svc.Patch(ctx, p.ID, input.BrokerProviderPatch{ConfigData: &newCfg})
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if string(got.ConfigData) != string(newCfg) {
		t.Errorf("config_data: got %s, want %s", string(got.ConfigData), string(newCfg))
	}
}

func TestBrokerProviderAdmin_Create_DuplicateSlug_Returns409(t *testing.T) {
	env := newBrokerProviderAdminTestEnv()
	ctx := context.Background()

	first := &resource.BrokerProvider{
		Slug:        "dup",
		DisplayName: "First",
		Protocol:    resource.ProtocolOAuth,
	}
	if err := env.svc.Create(ctx, first); err != nil {
		t.Fatalf("seed: %v", err)
	}

	second := &resource.BrokerProvider{
		Slug:        "dup",
		DisplayName: "Second",
		Protocol:    resource.ProtocolOAuth,
	}
	err := env.svc.Create(ctx, second)
	if err == nil {
		t.Fatal("expected conflict, got nil")
	}
	domErr, ok := err.(domain.Error)
	if !ok || domErr.Code() != domain.CodeConflict {
		t.Errorf("expected CodeConflict, got %v", err)
	}
}

func TestBrokerProviderAdmin_Patch_SlugCollision_Returns409(t *testing.T) {
	env := newBrokerProviderAdminTestEnv()
	ctx := context.Background()

	a := &resource.BrokerProvider{Slug: "alpha", DisplayName: "A", Protocol: resource.ProtocolOAuth}
	b := &resource.BrokerProvider{Slug: "bravo", DisplayName: "B", Protocol: resource.ProtocolOAuth}
	if err := env.svc.Create(ctx, a); err != nil {
		t.Fatalf("seed alpha: %v", err)
	}
	if err := env.svc.Create(ctx, b); err != nil {
		t.Fatalf("seed bravo: %v", err)
	}

	clash := "alpha"
	_, err := env.svc.Patch(ctx, b.ID, input.BrokerProviderPatch{Slug: &clash})
	if err == nil {
		t.Fatal("expected conflict, got nil")
	}
	domErr, ok := err.(domain.Error)
	if !ok || domErr.Code() != domain.CodeConflict {
		t.Errorf("expected CodeConflict, got %v", err)
	}
}

func TestBrokerProviderAdmin_Delete_FKBlock(t *testing.T) {
	env := newBrokerProviderAdminTestEnv()
	ctx := context.Background()

	p := &resource.BrokerProvider{
		Slug:        "fk-blocked",
		DisplayName: "Blocked",
		Protocol:    resource.ProtocolOAuth,
	}
	if err := env.svc.Create(ctx, p); err != nil {
		t.Fatalf("seed: %v", err)
	}
	env.providers.deleteFn = func(_ context.Context, _ string) error {
		return domain.ErrBrokerProviderHasReferences
	}

	err := env.svc.Delete(ctx, p.ID)
	if !errors.Is(err, domain.ErrBrokerProviderHasReferences) {
		t.Fatalf("expected ErrBrokerProviderHasReferences, got %v", err)
	}
	domErr, ok := err.(domain.Error)
	if !ok || domErr.Code() != domain.CodeConflict {
		t.Errorf("expected CodeConflict, got %v", err)
	}
}

func TestBrokerProviderAdmin_Delete_NotFound(t *testing.T) {
	env := newBrokerProviderAdminTestEnv()
	err := env.svc.Delete(context.Background(), "does-not-exist")
	if !errors.Is(err, domain.ErrResourceNotFound) {
		t.Fatalf("expected ErrResourceNotFound, got %v", err)
	}
}

func TestBrokerProviderAdmin_AuditRecordedOnEveryMutation(t *testing.T) {
	env := newBrokerProviderAdminTestEnv()
	ctx := context.Background()

	p := &resource.BrokerProvider{
		Slug:        "audited",
		DisplayName: "Audited",
		Protocol:    resource.ProtocolOAuth,
	}
	if err := env.svc.Create(ctx, p); err != nil {
		t.Fatalf("Create: %v", err)
	}

	displayName := "Audited (renamed)"
	if _, err := env.svc.Patch(ctx, p.ID, input.BrokerProviderPatch{DisplayName: &displayName}); err != nil {
		t.Fatalf("Patch: %v", err)
	}

	if err := env.svc.Delete(ctx, p.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	wantActions := map[audit.Action]bool{
		audit.ActionBrokerProviderCreated: false,
		audit.ActionBrokerProviderPatched: false,
		audit.ActionBrokerProviderDeleted: false,
	}
	for _, e := range env.audit.events {
		if _, ok := wantActions[e.Action]; ok {
			wantActions[e.Action] = true
		}
	}
	for action, seen := range wantActions {
		if !seen {
			t.Errorf("missing audit event for %s", action)
		}
	}
}

// TestBrokerProviderAdmin_Create_RejectsConfigDataNonObject locks the F4
// fix: config_data must be a JSON object, not null/array/string/number.
// Without this guard the brokerproto adapter would later choke on persisted
// non-object bytes at first vend.
func TestBrokerProviderAdmin_Create_RejectsConfigDataNonObject(t *testing.T) {
	env := newBrokerProviderAdminTestEnv()
	ctx := context.Background()

	cases := []struct {
		name string
		raw  []byte
	}{
		{"null", []byte("null")},
		{"array", []byte(`["x"]`)},
		{"string", []byte(`"hello"`)},
		{"number", []byte("42")},
		{"bool", []byte("true")},
		{"malformed", []byte("{not valid json")},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := &resource.BrokerProvider{
				Slug:        "x-" + tc.name,
				DisplayName: "X",
				Protocol:    resource.ProtocolOAuth,
				ConfigData:  tc.raw,
			}
			err := env.svc.Create(ctx, p)
			if err == nil {
				t.Fatalf("expected rejection for %s, got nil", tc.name)
			}
			domErr, ok := err.(domain.Error)
			if !ok || domErr.Code() != "invalid_request" {
				t.Errorf("expected invalid_request, got %v", err)
			}
		})
	}
}

// TestBrokerProviderAdmin_Patch_EmptyPatchIsNoOp locks the F5 fix.
func TestBrokerProviderAdmin_Patch_EmptyPatchIsNoOp(t *testing.T) {
	env := newBrokerProviderAdminTestEnv()
	ctx := context.Background()

	p := &resource.BrokerProvider{
		Slug:        "no-op",
		DisplayName: "X",
		Protocol:    resource.ProtocolOAuth,
	}
	if err := env.svc.Create(ctx, p); err != nil {
		t.Fatalf("seed: %v", err)
	}
	updatedBefore := p.UpdatedAt
	auditBefore := len(env.audit.events)

	got, err := env.svc.Patch(ctx, p.ID, input.BrokerProviderPatch{})
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if !got.UpdatedAt.Equal(updatedBefore) {
		t.Errorf("UpdatedAt bumped on empty patch: before=%v after=%v", updatedBefore, got.UpdatedAt)
	}
	if len(env.audit.events) != auditBefore {
		t.Errorf("audit emitted on empty patch: before=%d after=%d", auditBefore, len(env.audit.events))
	}
}

// TestBrokerProviderAdmin_List_ReturnsAll is the regression for audit
// finding F9: the service's List must round-trip the store's full
// slice. No filter argument exists at this level (BrokerProviders are a
// small set, ~10 max in v0.1.0-rc1).
func TestBrokerProviderAdmin_List_ReturnsAll(t *testing.T) {
	env := newBrokerProviderAdminTestEnv()
	ctx := context.Background()

	// Empty store → empty list, no error.
	got, err := env.svc.List(ctx)
	if err != nil {
		t.Fatalf("List on empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("List on empty: got %d rows, want 0", len(got))
	}

	// Seed three providers; List must return all.
	for _, slug := range []string{"alpha", "beta", "gamma"} {
		p := &resource.BrokerProvider{
			Slug: slug, DisplayName: slug, Protocol: resource.ProtocolOAuth,
		}
		if cerr := env.svc.Create(ctx, p); cerr != nil {
			t.Fatalf("seed %s: %v", slug, cerr)
		}
	}

	got, err = env.svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d rows, want 3", len(got))
	}
	seen := make(map[string]bool, 3)
	for _, p := range got {
		seen[p.Slug] = true
	}
	for _, want := range []string{"alpha", "beta", "gamma"} {
		if !seen[want] {
			t.Errorf("List missing %q", want)
		}
	}
}

// TestBrokerProviderAdmin_Create_RejectsRawSecretInConfigData is the
// regression for audit finding B12: literal credential values in
// config_data are rejected. Operators must use the *_ref convention.
func TestBrokerProviderAdmin_Create_RejectsRawSecretInConfigData(t *testing.T) {
	env := newBrokerProviderAdminTestEnv()
	ctx := context.Background()

	cases := []struct {
		name        string
		configRaw   string
		shouldOK    bool
		errContains string // expected substring when rejected
	}{
		{
			// A raw value in a ROUTED secret field (client_secret) is rejected by
			// the env-like SecretEncoder (no inline values), not the guard.
			name:        "raw_client_secret_rejected",
			configRaw:   `{"client_id":"x","client_secret":"raw-value"}`,
			shouldOK:    false,
			errContains: "inline values",
		},
		{
			// A raw value in a NON-routed key is rejected by the post-encode guard
			// (which runs even when no secret field is provided for routing).
			name:        "raw_password_rejected",
			configRaw:   `{"client_id":"x","admin_password":"hunter2"}`,
			shouldOK:    false,
			errContains: "_ref convention",
		},
		{
			name:      "client_secret_ref_accepted",
			configRaw: `{"client_id":"x","client_secret_ref":"GH_CLIENT_SECRET"}`,
			shouldOK:  true,
		},
		{
			name:      "api_key_env_accepted",
			configRaw: `{"api_key_env":"MY_API_KEY"}`,
			shouldOK:  true,
		},
		{
			name:      "empty_secret_value_accepted",
			configRaw: `{"client_secret":""}`,
			shouldOK:  true, // empty placeholder isn't the leak we're catching
		},
		{
			name:      "non_secret_keys_accepted",
			configRaw: `{"client_id":"abc","authorize_url":"https://x"}`,
			shouldOK:  true,
		},
		{
			name:        "uppercase_suffix_rejected",
			configRaw:   `{"My_SECRET":"raw"}`,
			shouldOK:    false, // case-insensitive suffix match
			errContains: "_ref convention",
		},
		{
			name:      "secret_validity_seconds_accepted",
			configRaw: `{"secret_validity_seconds":3600}`,
			shouldOK:  true, // doesn't end in _secret
		},
		{
			name:        "non_string_routed_secret_field_rejected",
			configRaw:   `{"client_secret":123}`,
			shouldOK:    false, // a routed secret field of the wrong JSON type is malformed input (400)
			errContains: "expected a JSON string",
		},
		{
			name:      "non_string_non_routed_key_accepted",
			configRaw: `{"My_SECRET":123}`,
			shouldOK:  true, // the raw-secret guard still only fires on string values for non-routed keys
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := &resource.BrokerProvider{
				Slug:        "bp-" + strings.ReplaceAll(tc.name, "_", "-"),
				DisplayName: "BP",
				Protocol:    resource.ProtocolOAuth,
				ConfigData:  []byte(tc.configRaw),
			}
			err := env.svc.Create(ctx, p)
			if tc.shouldOK && err != nil {
				t.Fatalf("expected accept, got %v", err)
			}
			if !tc.shouldOK {
				if err == nil {
					t.Fatal("expected rejection, got nil")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("expected error containing %q, got %v", tc.errContains, err)
				}
			}
		})
	}
}
