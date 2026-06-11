package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/admin/dto"
	"github.com/authplane/authserver/internal/domain/resource"
)

// runProviderCmd executes the provider cobra subtree against the supplied
// argv, capturing stdout. Cobra-level errors propagate to err so the test
// can assert on them; service-side state lives on the stub.
func runProviderCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return dispatchRoot(t, providerCmd, args)
}

func TestProviderCmd_Create_LoadsConfigDataFromFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "github-oauth.json")
	cfgBody := []byte(`{"client_id":"abc","client_secret_env":"AP_GH_SECRET","authorize_url":"https://github.com/login/oauth/authorize"}`)
	if err := writeFile(cfgPath, cfgBody); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	var captured *resource.BrokerProvider
	stub := &stubBrokerProviderAdmin{
		CreateFn: func(_ context.Context, p *resource.BrokerProvider) error {
			p.ID = "prov-123"
			captured = p
			return nil
		},
	}
	newTestCLIEnv(t, nil, stub, nil, nil)

	out, err := runProviderCmd(t, "create",
		"--slug", "github",
		"--display-name", "GitHub",
		"--protocol", "oauth",
		"--config-data", cfgPath,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v\nout=%s", err, out)
	}
	if captured == nil {
		t.Fatalf("expected stub.Create to receive the provider; got nil\nout=%s", out)
	}
	if captured.Slug != "github" || captured.DisplayName != "GitHub" || captured.Protocol != resource.ProtocolOAuth {
		t.Fatalf("unexpected provider passed to service: %+v", captured)
	}
	if !bytes.Equal(captured.ConfigData, cfgBody) {
		t.Fatalf("ConfigData was not round-tripped byte-for-byte: %q vs %q",
			string(captured.ConfigData), string(cfgBody))
	}
	if !strings.Contains(out, "id=prov-123") {
		t.Fatalf("expected output to include id=prov-123, got %q", out)
	}
}

func TestProviderCmd_Create_BadJSONFile_Returns1(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.json")
	if err := writeFile(cfgPath, []byte("{this is not valid json")); err != nil {
		t.Fatalf("seed bad config: %v", err)
	}

	stub := &stubBrokerProviderAdmin{
		CreateFn: func(_ context.Context, _ *resource.BrokerProvider) error {
			t.Fatalf("Create should NOT have been called when --config-data is invalid JSON")
			return nil
		},
	}
	newTestCLIEnv(t, nil, stub, nil, nil)

	_, err := runProviderCmd(t, "create",
		"--slug", "broken",
		"--display-name", "Broken",
		"--protocol", "oauth",
		"--config-data", cfgPath,
	)
	if err == nil {
		t.Fatalf("expected error from invalid JSON --config-data, got nil")
	}
	if !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("expected 'not valid JSON' in error, got %q", err.Error())
	}
}

func TestProviderCmd_Create_MissingFile_Returns1(t *testing.T) {
	stub := &stubBrokerProviderAdmin{
		CreateFn: func(_ context.Context, _ *resource.BrokerProvider) error {
			t.Fatalf("Create should NOT have been called when --config-data file is missing")
			return nil
		},
	}
	newTestCLIEnv(t, nil, stub, nil, nil)

	_, err := runProviderCmd(t, "create",
		"--slug", "missing",
		"--display-name", "Missing",
		"--protocol", "oauth",
		"--config-data", "/nonexistent/path/that/does/not/exist.json",
	)
	if err == nil {
		t.Fatalf("expected error for missing --config-data file, got nil")
	}
}

func TestProviderCmd_List_HumanAndJSON(t *testing.T) {
	rows := []*resource.BrokerProvider{
		{ID: "p1", Slug: "github", DisplayName: "GitHub", Protocol: resource.ProtocolOAuth, ConfigData: []byte(`{"k":1}`)},
		{ID: "p2", Slug: "stripe", DisplayName: "Stripe", Protocol: resource.ProtocolAPIKey, ConfigData: []byte(`{"k":2}`)},
	}
	stub := &stubBrokerProviderAdmin{
		ListFn: func(_ context.Context) ([]*resource.BrokerProvider, error) { return rows, nil },
	}
	newTestCLIEnv(t, nil, stub, nil, nil)

	out, err := runProviderCmd(t, "list")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "id=p1") || !strings.Contains(out, "id=p2") {
		t.Fatalf("expected both provider ids in output, got %q", out)
	}

	out, err = runProviderCmd(t, "list", "--json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got []dto.BrokerProviderView
	if jsonErr := json.Unmarshal([]byte(out), &got); jsonErr != nil {
		t.Fatalf("--json output is not valid JSON: %v\noutput=%s", jsonErr, out)
	}
	if len(got) != 2 || got[0].ID != "p1" {
		t.Fatalf("unexpected --json shape: %+v", got)
	}
}

func TestProviderCmd_Delete_PassesIDThrough(t *testing.T) {
	var deleted string
	stub := &stubBrokerProviderAdmin{
		DeleteFn: func(_ context.Context, id string) error {
			deleted = id
			return nil
		},
	}
	newTestCLIEnv(t, nil, stub, nil, nil)

	if _, err := runProviderCmd(t, "delete", "--id", "prov-xyz"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != "prov-xyz" {
		t.Fatalf("expected Delete to receive 'prov-xyz', got %q", deleted)
	}
}

func TestProviderCmd_Delete_PropagatesServiceError(t *testing.T) {
	stub := &stubBrokerProviderAdmin{
		DeleteFn: func(_ context.Context, _ string) error {
			return errors.New("not found")
		},
	}
	newTestCLIEnv(t, nil, stub, nil, nil)

	if _, err := runProviderCmd(t, "delete", "--id", "missing"); err == nil {
		t.Fatalf("expected error to propagate from service")
	}
}

// writeFile is a tiny helper for fixture seeding. Wraps os.WriteFile with
// 0o600 perms (tempdir-only writes) so the call sites don't repeat the
// permission literal.
func writeFile(path string, body []byte) error {
	return os.WriteFile(path, body, 0o600)
}
