package admin_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	apiadmin "github.com/authplane/authserver/api/admin"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// newAdminTestServerWithFronting wires the unified-resource admin surface
// AND the fronting-link admin surface. Mirrors
// newAdminTestServerWithUnifiedResources but additionally constructs
// FrontingService and threads it through the WithFrontingValidator option +
// the OptionalDeps.Fronting slot.
//
// Default-build (no integration tag) so CI runs these on every push, matching
// the openapi_drift_test.go cadence anchor ( hotfix).
func newAdminTestServerWithFronting(t *testing.T) *frontingTestEnv {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	adminSvc := services.NewAdminService(
		stores.Client, stores.User, stores.Token, stores.Audit,
		obs, nil,
		services.WithMachineTokenStore(stores.MachineToken),
		services.WithRevocationStore(stores.Revocation),
	)
	frontingSvc := services.NewFrontingService(
		stores.FrontingLink, stores.Resource, stores.TransactionMgr, obs, nil,
	)
	resourceAdminSvc := services.NewResourceAdminService(
		stores.Resource, stores.BrokerProvider, stores.Client, obs, nil,
		services.WithFrontingValidator(frontingSvc),
		services.WithResourceAdminTransactionManager(stores.TransactionMgr),
	)
	brokerProviderAdminSvc := services.NewBrokerProviderAdminService(
		stores.BrokerProvider, obs, nil,
	)

	srv := apiadmin.NewServer(context.Background(), config.AdminConfig{
		Enabled: true,
		Address: ":0",
		APIKey:  testAPIKey,
	}, adminSvc, obs, apiadmin.OptionalDeps{
		Resources:       &apiadmin.ResourceAdminDeps{Resources: resourceAdminSvc},
		BrokerProviders: &apiadmin.BrokerProviderAdminDeps{BrokerProviders: brokerProviderAdminSvc},
		Fronting:        &apiadmin.FrontingAdminDeps{Fronting: frontingSvc},
	})

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &frontingTestEnv{ts: ts}
}

type frontingTestEnv struct {
	ts *httptest.Server
}

func (e *frontingTestEnv) doJSON(t *testing.T, method, path string, body any) *http.Response {
	t.Helper()
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, e.ts.URL+path, bytesReader(b))
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s %s: %v", method, path, err)
	}
	return resp
}

func bytesReader(b []byte) *byteReadCloser { return &byteReadCloser{b: b} }

type byteReadCloser struct {
	b   []byte
	pos int
}

func (r *byteReadCloser) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}

func (r *byteReadCloser) Close() error { return nil }

// seedMintForFronting creates a Mint resource via the public admin API with
// the supplied scope names. Returns the slug.
func (e *frontingTestEnv) seedMintForFronting(t *testing.T, slug string, scopes []string) string {
	t.Helper()
	scopeViews := make([]map[string]any, len(scopes))
	for i, s := range scopes {
		scopeViews[i] = map[string]any{"name": s}
	}
	body := map[string]any{
		"slug":         slug,
		"backend_kind": "mint",
		"display_name": slug,
		"scopes":       scopeViews,
	}
	resp := e.doJSON(t, "POST", "/admin/resources", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("seed mint %q: %d %s", slug, resp.StatusCode, string(b))
	}
	return slug
}

// --- tests ---

func TestAdmin_Fronting_AuthRequired(t *testing.T) {
	env := newAdminTestServerWithFronting(t)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, env.ts.URL+"/admin/fronting", nil)
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", resp.StatusCode)
	}
}

func TestAdmin_Fronting_FullCRUD(t *testing.T) {
	env := newAdminTestServerWithFronting(t)
	env.seedMintForFronting(t, "gw-1", []string{"read", "write"})
	env.seedMintForFronting(t, "api-1", []string{"R", "W"})

	// CREATE.
	createBody := map[string]any{
		"source": "gw-1",
		"target": "api-1",
		"scope_map": map[string][]string{
			"read":  {"R"},
			"write": {"W"},
		},
	}
	resp := env.doJSON(t, "POST", "/admin/fronting", createBody)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: status %d body %s", resp.StatusCode, string(b))
	}
	var created map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created["source_slug"] != "gw-1" || created["target_slug"] != "api-1" {
		t.Errorf("create response shape: %v", created)
	}

	// GET.
	getResp := env.doJSON(t, "GET", "/admin/fronting/gw-1/api-1", nil)
	defer func() { _ = getResp.Body.Close() }()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get: status %d", getResp.StatusCode)
	}

	// LIST.
	listResp := env.doJSON(t, "GET", "/admin/fronting?source=gw-1", nil)
	defer func() { _ = listResp.Body.Close() }()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list: status %d", listResp.StatusCode)
	}
	var listed []map[string]any
	_ = json.NewDecoder(listResp.Body).Decode(&listed)
	if len(listed) != 1 {
		t.Errorf("list source=gw-1: got %d entries, want 1", len(listed))
	}

	// PATCH (scope_map).
	patchBody := map[string]any{
		"scope_map": map[string][]string{
			"read": {"R"},
		},
	}
	patchResp := env.doJSON(t, "PATCH", "/admin/fronting/gw-1/api-1", patchBody)
	defer func() { _ = patchResp.Body.Close() }()
	if patchResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(patchResp.Body)
		t.Fatalf("patch: status %d body %s", patchResp.StatusCode, string(b))
	}
	var patched map[string]any
	_ = json.NewDecoder(patchResp.Body).Decode(&patched)
	sm, _ := patched["scope_map"].(map[string]any)
	if _, hasWrite := sm["write"]; hasWrite {
		t.Errorf("patch did not drop 'write' key: %v", sm)
	}

	// LIST_FOR_RESOURCE.
	rfResp := env.doJSON(t, "GET", "/admin/resources/gw-1/fronting", nil)
	defer func() { _ = rfResp.Body.Close() }()
	if rfResp.StatusCode != http.StatusOK {
		t.Fatalf("resource fronting: status %d", rfResp.StatusCode)
	}
	var rf map[string]any
	_ = json.NewDecoder(rfResp.Body).Decode(&rf)
	fronts, _ := rf["fronts"].([]any)
	frontedBy, _ := rf["fronted_by"].([]any)
	if len(fronts) != 1 || len(frontedBy) != 0 {
		t.Errorf("expected 1 front, 0 fronted_by; got fronts=%d fronted_by=%d", len(fronts), len(frontedBy))
	}

	// DELETE.
	delResp := env.doJSON(t, "DELETE", "/admin/fronting/gw-1/api-1", nil)
	defer func() { _ = delResp.Body.Close() }()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: status %d, want 204", delResp.StatusCode)
	}

	// GET after delete: 404.
	missResp := env.doJSON(t, "GET", "/admin/fronting/gw-1/api-1", nil)
	defer func() { _ = missResp.Body.Close() }()
	if missResp.StatusCode != http.StatusNotFound {
		t.Fatalf("get after delete: %d, want 404", missResp.StatusCode)
	}
}

func TestAdmin_Fronting_DryRun_DoesNotPersist(t *testing.T) {
	env := newAdminTestServerWithFronting(t)
	env.seedMintForFronting(t, "gw-dry", []string{"a"})
	env.seedMintForFronting(t, "api-dry", []string{"A"})

	body := map[string]any{
		"source":    "gw-dry",
		"target":    "api-dry",
		"scope_map": map[string][]string{"a": {"A"}},
	}
	resp := env.doJSON(t, "POST", "/admin/fronting?dry_run=true", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("dry_run: status %d body %s", resp.StatusCode, string(b))
	}

	// Verify no row persisted.
	miss := env.doJSON(t, "GET", "/admin/fronting/gw-dry/api-dry", nil)
	defer func() { _ = miss.Body.Close() }()
	if miss.StatusCode != http.StatusNotFound {
		t.Fatalf("dry_run persisted: get returned %d", miss.StatusCode)
	}
}

func TestAdmin_Fronting_DryRun_RejectsInvalid(t *testing.T) {
	env := newAdminTestServerWithFronting(t)
	env.seedMintForFronting(t, "gw-bad", []string{"a"})
	env.seedMintForFronting(t, "api-bad", []string{"A"})

	body := map[string]any{
		"source":    "gw-bad",
		"target":    "api-bad",
		"scope_map": map[string][]string{"a": {"NOT_ON_TARGET"}},
	}
	resp := env.doJSON(t, "POST", "/admin/fronting?dry_run=true", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("dry_run invalid: status %d body %s", resp.StatusCode, string(b))
	}
}

// TestAdmin_Fronting_Patch_EmptyScopeMap_400 verifies the wire-contract
// distinction at the HTTP boundary: PATCH `{}` (no scope_map field) is a
// no-op and returns 200 with the existing data; PATCH `{"scope_map": {}}`
// is an explicit wipe attempt and rejects 400. Mirrors the service-level
// PATCH-dirty contract test.
func TestAdmin_Fronting_Patch_EmptyScopeMap_400(t *testing.T) {
	env := newAdminTestServerWithFronting(t)
	env.seedMintForFronting(t, "gw-pe", []string{"a"})
	env.seedMintForFronting(t, "api-pe", []string{"A"})

	// Seed a link to patch.
	createResp := env.doJSON(t, "POST", "/admin/fronting", map[string]any{
		"source": "gw-pe", "target": "api-pe",
		"scope_map": map[string][]string{"a": {"A"}},
	})
	_ = createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("seed link: %d", createResp.StatusCode)
	}

	// PATCH `{}` — no scope_map field — is a no-op (200, unchanged row).
	noopResp := env.doJSON(t, "PATCH", "/admin/fronting/gw-pe/api-pe", map[string]any{})
	defer func() { _ = noopResp.Body.Close() }()
	if noopResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(noopResp.Body)
		t.Fatalf("noop patch: status %d body %s", noopResp.StatusCode, string(b))
	}

	// PATCH `{"scope_map": {}}` — explicit wipe — must reject 400.
	emptyResp := env.doJSON(t, "PATCH", "/admin/fronting/gw-pe/api-pe", map[string]any{
		"scope_map": map[string][]string{},
	})
	defer func() { _ = emptyResp.Body.Close() }()
	if emptyResp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(emptyResp.Body)
		t.Fatalf("empty patch: status %d body %s", emptyResp.StatusCode, string(b))
	}

	// Underlying row still has the original scope_map.
	getResp := env.doJSON(t, "GET", "/admin/fronting/gw-pe/api-pe", nil)
	defer func() { _ = getResp.Body.Close() }()
	var got map[string]any
	_ = json.NewDecoder(getResp.Body).Decode(&got)
	sm, _ := got["scope_map"].(map[string]any)
	if _, ok := sm["a"]; !ok {
		t.Errorf("rejected patch clobbered the row: %v", sm)
	}
}

func TestAdmin_Fronting_Create_DuplicatePair_409(t *testing.T) {
	env := newAdminTestServerWithFronting(t)
	env.seedMintForFronting(t, "gw-dup", []string{"a"})
	env.seedMintForFronting(t, "api-dup", []string{"A"})

	body := map[string]any{
		"source":    "gw-dup",
		"target":    "api-dup",
		"scope_map": map[string][]string{"a": {"A"}},
	}
	r1 := env.doJSON(t, "POST", "/admin/fronting", body)
	_ = r1.Body.Close()
	if r1.StatusCode != http.StatusCreated {
		t.Fatalf("first create: %d", r1.StatusCode)
	}
	r2 := env.doJSON(t, "POST", "/admin/fronting", body)
	defer func() { _ = r2.Body.Close() }()
	if r2.StatusCode != http.StatusConflict {
		t.Fatalf("dup create: status %d, want 409", r2.StatusCode)
	}
}

func TestAdmin_Fronting_ResourceDelete_Conflict_AndCascade(t *testing.T) {
	env := newAdminTestServerWithFronting(t)
	env.seedMintForFronting(t, "gw-c", []string{"a"})
	env.seedMintForFronting(t, "api-c", []string{"A"})

	// Resolve the source resource id (admin DELETE path uses {id}).
	listResp := env.doJSON(t, "GET", "/admin/resources?slug=gw-c", nil)
	defer func() { _ = listResp.Body.Close() }()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("lookup: %d", listResp.StatusCode)
	}
	var srcRes map[string]any
	_ = json.NewDecoder(listResp.Body).Decode(&srcRes)
	srcID, _ := srcRes["id"].(string)
	if srcID == "" {
		t.Fatal("empty source id")
	}

	// Seed a fronting link.
	body := map[string]any{
		"source":    "gw-c",
		"target":    "api-c",
		"scope_map": map[string][]string{"a": {"A"}},
	}
	r := env.doJSON(t, "POST", "/admin/fronting", body)
	_ = r.Body.Close()
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("seed link: %d", r.StatusCode)
	}

	// DELETE resource without cascade → 409 with dependents.
	conflictResp := env.doJSON(t, "DELETE", "/admin/resources/"+srcID, nil)
	defer func() { _ = conflictResp.Body.Close() }()
	if conflictResp.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(conflictResp.Body)
		t.Fatalf("delete without cascade: status %d body %s", conflictResp.StatusCode, string(b))
	}
	var conflictBody map[string]any
	_ = json.NewDecoder(conflictResp.Body).Decode(&conflictBody)
	deps, _ := conflictBody["dependents"].([]any)
	if len(deps) != 1 {
		t.Errorf("expected 1 dependent in 409, got %v", conflictBody)
	}

	// DELETE with cascade=true → 204.
	cascadeResp := env.doJSON(t, "DELETE", "/admin/resources/"+srcID+"?cascade=true", nil)
	defer func() { _ = cascadeResp.Body.Close() }()
	if cascadeResp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(cascadeResp.Body)
		t.Fatalf("cascade delete: status %d body %s", cascadeResp.StatusCode, string(b))
	}

	// Resource gone.
	getResp := env.doJSON(t, "GET", "/admin/resources/"+srcID, nil)
	defer func() { _ = getResp.Body.Close() }()
	if getResp.StatusCode != http.StatusNotFound {
		t.Fatalf("resource still present: %d", getResp.StatusCode)
	}
	// Link gone.
	miss := env.doJSON(t, "GET", "/admin/fronting/gw-c/api-c", nil)
	defer func() { _ = miss.Body.Close() }()
	if miss.StatusCode != http.StatusNotFound {
		t.Fatalf("link still present: %d", miss.StatusCode)
	}
}
