package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/admin/dto"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/input"
)

func runGrantCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return dispatchRoot(t, grantCmd, args)
}

func TestGrantCmd_ListUserGrants_BothShapes(t *testing.T) {
	consents := []*resource.ConsentGrant{
		{ID: "c1", UserID: "u1", ClientID: "agent-a", ResourceID: "res-1", Scopes: []string{"repo"}},
	}
	brokers := []*resource.BrokerGrant{
		{ID: "b1", UserID: "u1", BrokerProviderID: "prov-github", ScopesGranted: []string{"repo"}, Version: 1, EncBackend: "vault"},
	}
	stub := &stubGrantAdmin{
		ListForUserFn: func(_ context.Context, userID string) (input.UserGrants, error) {
			if userID != "u1" {
				t.Fatalf("expected userID=u1, got %q", userID)
			}
			return input.UserGrants{Consent: consents, Broker: brokers}, nil
		},
	}
	newTestCLIEnv(t, nil, nil, stub, nil)

	out, err := runGrantCmd(t, "list-user-grants", "--user", "u1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"consent_grants (1)", "id=c1", "broker_grants (1)", "id=b1"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in human output: %q", want, out)
		}
	}

	out, err = runGrantCmd(t, "list-user-grants", "--user", "u1", "--json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got dto.UserGrantsView
	if jsonErr := json.Unmarshal([]byte(out), &got); jsonErr != nil {
		t.Fatalf("--json output is not valid JSON: %v\noutput=%s", jsonErr, out)
	}
	if len(got.ConsentGrants) != 1 || got.ConsentGrants[0].ID != "c1" {
		t.Fatalf("unexpected consent_grants in --json output: %+v", got.ConsentGrants)
	}
	if len(got.BrokerGrants) != 1 || got.BrokerGrants[0].ID != "b1" {
		t.Fatalf("unexpected broker_grants in --json output: %+v", got.BrokerGrants)
	}
	// Defense-in-depth: the JSON output must NEVER carry credential_data,
	// even if a future contributor adds it to the domain type. The wire-side
	// test in api/admin/handlers_test.go covers the HTTP path; this is the
	// CLI-side parallel.
	if strings.Contains(out, "credential_data") {
		t.Fatalf("broker_grants JSON output must NEVER include credential_data: %s", out)
	}
}

func TestGrantCmd_RevokeConsent_CallsService(t *testing.T) {
	var revoked string
	stub := &stubGrantAdmin{
		RevokeConsentFn: func(_ context.Context, id string) error {
			revoked = id
			return nil
		},
	}
	newTestCLIEnv(t, nil, nil, stub, nil)

	out, err := runGrantCmd(t, "revoke-consent", "--id", "grant-xyz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if revoked != "grant-xyz" {
		t.Fatalf("expected RevokeConsent to receive 'grant-xyz', got %q", revoked)
	}
	if !strings.Contains(out, "revoked consent grant: id=grant-xyz") {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestGrantCmd_RevokeBroker_CallsService(t *testing.T) {
	var revoked string
	stub := &stubGrantAdmin{
		RevokeBrokerFn: func(_ context.Context, id string) error {
			revoked = id
			return nil
		},
	}
	newTestCLIEnv(t, nil, nil, stub, nil)

	out, err := runGrantCmd(t, "revoke-broker", "--id", "broker-grant-7")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if revoked != "broker-grant-7" {
		t.Fatalf("expected RevokeBroker to receive 'broker-grant-7', got %q", revoked)
	}
	if !strings.Contains(out, "revoked broker grant: id=broker-grant-7") {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestGrantCmd_RequiresFlags(t *testing.T) {
	stub := &stubGrantAdmin{}
	newTestCLIEnv(t, nil, nil, stub, nil)

	if _, err := runGrantCmd(t, "list-user-grants"); err == nil {
		t.Errorf("expected error when --user is missing")
	}
	if _, err := runGrantCmd(t, "revoke-consent"); err == nil {
		t.Errorf("expected error when --id is missing")
	}
	if _, err := runGrantCmd(t, "revoke-broker"); err == nil {
		t.Errorf("expected error when --id is missing")
	}
}

func TestGrantCmd_RevokeConsent_PropagatesError(t *testing.T) {
	stub := &stubGrantAdmin{
		RevokeConsentFn: func(_ context.Context, _ string) error {
			return errors.New("boom")
		},
	}
	newTestCLIEnv(t, nil, nil, stub, nil)

	if _, err := runGrantCmd(t, "revoke-consent", "--id", "x"); err == nil {
		t.Fatalf("expected error to propagate from service")
	}
}
