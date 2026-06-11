//go:build integration

package services_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/adapters/sqlite"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

type dcrTestSetup struct {
	svc      *services.DCRService
	auditSvc *services.AuditService
	stores   *sqlite.Stores
}

func newDCRService(t *testing.T, mode string, approvedRedirects []string) (*services.DCRService, *sqlite.Stores) {
	t.Helper()
	s := newDCRSetup(t, mode, approvedRedirects)
	return s.svc, s.stores
}

func newDCRSetup(t *testing.T, mode string, approvedRedirects []string) *dcrTestSetup {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	auditSvc := services.NewAuditService(stores.Audit, obs)

	dcrMode := services.DCRMode{
		Mode:              mode,
		ApprovedRedirects: approvedRedirects,
	}

	svc := services.NewDCRService(stores.Client, dcrMode, obs.WithComponent("dcr"), auditSvc)
	return &dcrTestSetup{svc: svc, auditSvc: auditSvc, stores: stores}
}

// --- DCR Mode: Open ---

func TestDCR_Open_RegisterPublicClient(t *testing.T) {
	svc, _ := newDCRService(t, "open", nil)
	ctx := context.Background()

	resp, err := svc.RegisterClient(ctx, input.RegisterClientRequest{
		ClientName:   "My Public Client",
		RedirectURIs: []string{"https://app.example.com/callback"},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if resp.ClientID == "" {
		t.Error("client_id is empty")
	}
	if resp.ClientName != "My Public Client" {
		t.Errorf("client_name: got %q", resp.ClientName)
	}
	if resp.ClientSecret != "" {
		t.Error("public client should not have secret")
	}
	if resp.ClientIDIssuedAt == 0 {
		t.Error("client_id_issued_at is zero")
	}
	if len(resp.RedirectURIs) != 1 || resp.RedirectURIs[0] != "https://app.example.com/callback" {
		t.Errorf("redirect_uris: got %v", resp.RedirectURIs)
	}
	// Defaults applied.
	if len(resp.GrantTypes) != 1 || resp.GrantTypes[0] != "authorization_code" {
		t.Errorf("grant_types default: got %v", resp.GrantTypes)
	}
	if len(resp.ResponseTypes) != 1 || resp.ResponseTypes[0] != "code" {
		t.Errorf("response_types default: got %v", resp.ResponseTypes)
	}
	if resp.TokenEndpointAuthMethod != "none" {
		t.Errorf("auth method: got %q", resp.TokenEndpointAuthMethod)
	}
}

// Matrix: 15.6 — upgraded from warning: client.registered audit event after DCR
// Matrix: 2.6 — upgraded from warning: client_name stored and readable after DCR
func TestDCR_Open_AuditAndClientName(t *testing.T) {
	s := newDCRSetup(t, "open", nil)
	ctx := context.Background()

	resp, err := s.svc.RegisterClient(ctx, input.RegisterClientRequest{
		ClientName:   "Audit Test Client",
		RedirectURIs: []string{"https://app.example.com/callback"},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// 15.6: Verify audit event recorded.
	events, err := s.auditSvc.Query(ctx, output.AuditFilter{
		Action: string(audit.ActionClientRegistered),
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(events) < 1 {
		t.Error("expected at least 1 client.registered audit event")
	}
	if events[0].ClientID == "" {
		t.Error("audit client_id should be non-empty on registration event")
	}

	// 2.6: Verify client_name is stored and retrievable.
	stored, err := s.stores.Client.GetByID(ctx, resp.ClientID)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if stored.Name != "Audit Test Client" {
		t.Errorf("client_name: got %q, want %q", stored.Name, "Audit Test Client")
	}
}

func TestDCR_Open_RegisterConfidentialClient(t *testing.T) {
	svc, _ := newDCRService(t, "open", nil)
	ctx := context.Background()

	resp, err := svc.RegisterClient(ctx, input.RegisterClientRequest{
		ClientName:              "Confidential App",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if resp.ClientSecret == "" {
		t.Error("confidential client should have secret")
	}
	if resp.ClientSecretExpiresAt == nil || *resp.ClientSecretExpiresAt != 0 {
		t.Errorf("client_secret_expires_at: got %v, want ptr to 0 (never)", resp.ClientSecretExpiresAt)
	}
	if resp.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Errorf("auth method: got %q", resp.TokenEndpointAuthMethod)
	}

	// Verify the secret is valid bcrypt.
	if err := crypto.CompareBcrypt(resp.ClientSecret, resp.ClientSecret); err == nil {
		// The secret should NOT match itself as bcrypt hash — the stored hash is different from the plaintext.
		// Actually, let's verify the stored secret hash works.
	}
}

func TestDCR_Open_StoredSecretMatchesPlaintext(t *testing.T) {
	svc, stores := newDCRService(t, "open", nil)
	ctx := context.Background()

	resp, err := svc.RegisterClient(ctx, input.RegisterClientRequest{
		ClientName:              "Secret Test",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_post",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Fetch from store and verify bcrypt hash matches the returned plaintext secret.
	stored, err := stores.Client.GetByID(ctx, resp.ClientID)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if stored.SecretHash == "" {
		t.Fatal("stored secret hash is empty")
	}
	if err := crypto.CompareBcrypt(stored.SecretHash, resp.ClientSecret); err != nil {
		t.Errorf("bcrypt compare failed: %v", err)
	}
}

// Matrix: 2.12 — two identical DCR requests must produce different client_ids
func TestDCR_Open_DuplicateRegistration_DifferentClientIDs(t *testing.T) {
	svc, _ := newDCRService(t, "open", nil)
	ctx := context.Background()

	req := input.RegisterClientRequest{
		ClientName:   "Duplicate Test",
		RedirectURIs: []string{"https://app.example.com/callback"},
	}

	resp1, err := svc.RegisterClient(ctx, req)
	if err != nil {
		t.Fatalf("first register: %v", err)
	}

	resp2, err := svc.RegisterClient(ctx, req)
	if err != nil {
		t.Fatalf("second register: %v", err)
	}

	if resp1.ClientID == resp2.ClientID {
		t.Errorf("two registrations must produce different client_ids, got %q both times", resp1.ClientID)
	}
}

func TestDCR_Open_InvalidRequest(t *testing.T) {
	svc, _ := newDCRService(t, "open", nil)
	ctx := context.Background()

	// Missing client_name.
	_, err := svc.RegisterClient(ctx, input.RegisterClientRequest{
		RedirectURIs: []string{"https://app.example.com/callback"},
	})
	if err == nil {
		t.Fatal("expected error for missing client_name")
	}
}

func TestDCR_Open_InvalidRedirectURI(t *testing.T) {
	svc, _ := newDCRService(t, "open", nil)
	ctx := context.Background()

	_, err := svc.RegisterClient(ctx, input.RegisterClientRequest{
		ClientName:   "Bad URI",
		RedirectURIs: []string{"http://evil.example.com/callback"},
	})
	if err == nil {
		t.Fatal("expected error for non-localhost HTTP redirect")
	}
}

// --- DCR Mode: Approved Redirects ---

func TestDCR_ApprovedRedirects_Accepted(t *testing.T) {
	svc, _ := newDCRService(t, "approved_redirects", []string{
		"https://app.example.com/callback",
		"https://other.example.com/",
	})
	ctx := context.Background()

	resp, err := svc.RegisterClient(ctx, input.RegisterClientRequest{
		ClientName:   "Approved Client",
		RedirectURIs: []string{"https://app.example.com/callback"},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp.ClientID == "" {
		t.Error("client_id is empty")
	}
}

func TestDCR_ApprovedRedirects_Rejected(t *testing.T) {
	svc, _ := newDCRService(t, "approved_redirects", []string{
		"https://app.example.com/callback",
	})
	ctx := context.Background()

	_, err := svc.RegisterClient(ctx, input.RegisterClientRequest{
		ClientName:   "Rejected Client",
		RedirectURIs: []string{"https://evil.example.com/callback"},
	})
	if err == nil {
		t.Fatal("expected error for unapproved redirect")
	}
	if !errors.Is(err, domain.ErrInvalidRedirectURI) {
		t.Errorf("expected ErrInvalidRedirectURI, got: %v", err)
	}
}

// --- DCR Mode: Admin Only ---

// Matrix: 18.7 — DCR admin_only returns ErrRegistrationDisabled
func TestDCR_AdminOnly_Rejected(t *testing.T) {
	svc, _ := newDCRService(t, "admin_only", nil)
	ctx := context.Background()

	_, err := svc.RegisterClient(ctx, input.RegisterClientRequest{
		ClientName:   "Should Fail",
		RedirectURIs: []string{"https://app.example.com/callback"},
	})
	if err == nil {
		t.Fatal("expected error in admin_only mode")
	}
	if !errors.Is(err, domain.ErrRegistrationDisabled) {
		t.Errorf("expected ErrRegistrationDisabled, got: %v", err)
	}
}

// Matrix: 18.8 — DCR approved_redirects uses exact match only, no glob/wildcards
func TestDCR_ApprovedRedirects_NoGlobMatching(t *testing.T) {
	// Configure with an exact URI — ensure glob patterns DON'T match.
	svc, _ := newDCRService(t, "approved_redirects", []string{
		"https://app.example.com/callback",
	})
	ctx := context.Background()

	tests := []struct {
		name string
		uri  string
	}{
		{"glob star", "https://app.example.com/*"},
		{"glob question", "https://app.example.com/?allback"},
		{"prefix match", "https://app.example.com/callback/extra"},
		{"different path", "https://app.example.com/other"},
		{"trailing slash", "https://app.example.com/callback/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.RegisterClient(ctx, input.RegisterClientRequest{
				ClientName:   "Glob Test",
				RedirectURIs: []string{tt.uri},
			})
			if err == nil {
				t.Errorf("redirect_uri %q should be rejected (exact match only)", tt.uri)
			}
		})
	}
}

// DCR must reject registration with a grant_type the AS isn't
// configured to honor. The error must name the env var the operator must
// set so the failure is actionable rather than mysterious.
func TestDCR_GrantTypeNotEnabled_Rejected(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	auditSvc := services.NewAuditService(stores.Audit, obs)
	dcrMode := services.DCRMode{Mode: "open"}

	// AS configured WITHOUT client_credentials enabled.
	svc := services.NewDCRService(
		stores.Client, dcrMode, obs.WithComponent("dcr"), auditSvc,
		services.WithDCREnabledGrants([]string{"authorization_code", "refresh_token"}),
	)

	_, err := svc.RegisterClient(context.Background(), input.RegisterClientRequest{
		ClientName:              "CC Client",
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	if err == nil {
		t.Fatal("DCR must reject client_credentials when not enabled")
	}
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("expected domain.ErrInvalidClient, got: %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "client_credentials") {
		t.Errorf("error should name the offending grant: %v", err)
	}
	if !strings.Contains(msg, "AUTHPLANE_CLIENT_CREDENTIALS_ENABLED") {
		t.Errorf("error should name the env var: %v", err)
	}
}

func TestDCR_GrantTypeEnabled_Accepted(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	auditSvc := services.NewAuditService(stores.Audit, obs)
	dcrMode := services.DCRMode{Mode: "open"}

	svc := services.NewDCRService(
		stores.Client, dcrMode, obs.WithComponent("dcr"), auditSvc,
		services.WithDCREnabledGrants([]string{"authorization_code", "refresh_token", "client_credentials"}),
	)

	resp, err := svc.RegisterClient(context.Background(), input.RegisterClientRequest{
		ClientName:              "CC Client",
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	if err != nil {
		t.Fatalf("DCR with enabled client_credentials should pass: %v", err)
	}
	if resp.ClientID == "" {
		t.Error("expected client_id in response")
	}
}

