//go:build integration

package admin_test

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// Tests for — slug-friendly admin API.
//
// Read-side: GET /admin/resources?slug=... and GET /admin/broker-providers?slug=...
// short-circuit to a single object (or 404), matching the shape of
// GET .../admin/<resource>/{id}.
//
// Write-side: POST /admin/resources accepts `broker_provider_slug` alongside
// the existing `broker_provider_id` so onboarding scripts no longer have
// to list-and-translate before creating a Broker resource.
//
// Every fixture (broker providers, resources) is created via the public
// admin API. No store seeds, no internal/services imports — Gate 0.

// --- read-side: resources ---

func TestAdmin_ResourcesLookup_BySlug_Hit(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	slug := adminCreateMintResource(t, env, "lookup-mint")

	resp := env.doRequest(t, "GET", "/admin/resources?slug="+slug, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d, want 200; body %s", resp.StatusCode, string(b))
	}

	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["slug"] != slug {
		t.Errorf("slug: got %v, want %q", out["slug"], slug)
	}
	if _, ok := out["id"].(string); !ok {
		t.Errorf("expected id field in single-object response, got %v", out)
	}
}

func TestAdmin_ResourcesLookup_BySlug_Miss(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)

	resp := env.doRequest(t, "GET", "/admin/resources?slug=does-not-exist", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d, want 404; body %s", resp.StatusCode, string(b))
	}
}

// Slug-lookup must short-circuit, not silently combine with list filters.
// If an operator sends both `slug` and `backend_kind`, they probably think
// they're filtering — surface a 400 so the misunderstanding is loud.
func TestAdmin_ResourcesLookup_BySlug_RejectsCombiningWithListFilters(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	slug := adminCreateMintResource(t, env, "lookup-conflict")

	cases := []string{
		"/admin/resources?slug=" + slug + "&backend_kind=mint",
		"/admin/resources?slug=" + slug + "&broker_provider_id=anything",
		"/admin/resources?slug=" + slug + "&limit=10",
		"/admin/resources?slug=" + slug + "&offset=0",
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			resp := env.doRequest(t, "GET", path, nil)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status %d, want 400 for %s", resp.StatusCode, path)
			}
		})
	}
}

// Sanity-check: the existing list path (no `slug=`) is unchanged.
func TestAdmin_ResourcesLookup_NoSlugReturnsListUnchanged(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	adminCreateMintResource(t, env, "list-still-works-1")
	adminCreateMintResource(t, env, "list-still-works-2")

	resp := env.doRequest(t, "GET", "/admin/resources", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}

	var out []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) < 2 {
		t.Errorf("expected at least 2 resources in list, got %d", len(out))
	}
}

// --- read-side: broker providers ---

func TestAdmin_BrokerProvidersLookup_BySlug_Hit(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	slug := "bp-lookup-hit"
	bpResp := env.doRequest(t, "POST", "/admin/broker-providers", map[string]any{
		"slug":         slug,
		"display_name": slug,
		"protocol":     "oauth",
		"config_data":  map[string]any{},
	})
	defer bpResp.Body.Close()
	if bpResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(bpResp.Body)
		t.Fatalf("seed broker provider: %d %s", bpResp.StatusCode, string(b))
	}
	var bp map[string]any
	json.NewDecoder(bpResp.Body).Decode(&bp)
	wantID := bp["id"].(string)

	resp := env.doRequest(t, "GET", "/admin/broker-providers?slug="+slug, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d, want 200; body %s", resp.StatusCode, string(b))
	}

	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["slug"] != slug {
		t.Errorf("slug: got %v, want %q", out["slug"], slug)
	}
	if out["id"] != wantID {
		t.Errorf("id: got %v, want %q", out["id"], wantID)
	}
}

func TestAdmin_BrokerProvidersLookup_BySlug_Miss(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)

	resp := env.doRequest(t, "GET", "/admin/broker-providers?slug=no-such-provider", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", resp.StatusCode)
	}
}

// --- write-side: POST /admin/resources accepts broker_provider_slug ---

func TestAdmin_Resources_Create_AcceptsBrokerProviderSlug(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)

	bpResp := env.doRequest(t, "POST", "/admin/broker-providers", map[string]any{
		"slug":         "github-create-bp-slug",
		"display_name": "GitHub",
		"protocol":     "oauth",
		"config_data":  map[string]any{},
	})
	defer bpResp.Body.Close()
	if bpResp.StatusCode != http.StatusCreated {
		t.Fatalf("seed broker provider: %d", bpResp.StatusCode)
	}
	var bp map[string]any
	json.NewDecoder(bpResp.Body).Decode(&bp)
	wantProviderID, _ := bp["id"].(string)

	// Create the broker resource using ONLY broker_provider_slug — the
	// happy path.
	createBody := map[string]any{
		"slug":                 "gh-by-slug",
		"uri":                  "https://github.example/api",
		"backend_kind":         "broker",
		"broker_provider_slug": "github-create-bp-slug",
		"display_name":         "GitHub by slug",
	}
	resp := env.doRequest(t, "POST", "/admin/resources", createBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: %d %s", resp.StatusCode, string(b))
	}
	var created map[string]any
	json.NewDecoder(resp.Body).Decode(&created)
	if created["broker_provider_id"] != wantProviderID {
		t.Errorf("broker_provider_id: got %v, want %q", created["broker_provider_id"], wantProviderID)
	}
}

func TestAdmin_Resources_Create_AcceptsBothWhenConsistent(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)

	bpResp := env.doRequest(t, "POST", "/admin/broker-providers", map[string]any{
		"slug":         "both-consistent-bp",
		"display_name": "X",
		"protocol":     "oauth",
		"config_data":  map[string]any{},
	})
	defer bpResp.Body.Close()
	var bp map[string]any
	json.NewDecoder(bpResp.Body).Decode(&bp)
	bpID, _ := bp["id"].(string)

	resp := env.doRequest(t, "POST", "/admin/resources", map[string]any{
		"slug":                 "both-consistent-res",
		"backend_kind":         "broker",
		"broker_provider_id":   bpID,
		"broker_provider_slug": "both-consistent-bp",
		"display_name":         "Both",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: %d %s", resp.StatusCode, string(b))
	}
}

func TestAdmin_Resources_Create_RejectsConflictingProviderRefs(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)

	// Two distinct providers — the slug refers to one, the id to the other.
	bp1 := env.doRequest(t, "POST", "/admin/broker-providers", map[string]any{
		"slug": "bp-one", "display_name": "1", "protocol": "oauth", "config_data": map[string]any{},
	})
	defer bp1.Body.Close()
	var bp1Body map[string]any
	json.NewDecoder(bp1.Body).Decode(&bp1Body)

	bp2 := env.doRequest(t, "POST", "/admin/broker-providers", map[string]any{
		"slug": "bp-two", "display_name": "2", "protocol": "oauth", "config_data": map[string]any{},
	})
	defer bp2.Body.Close()
	var bp2Body map[string]any
	json.NewDecoder(bp2.Body).Decode(&bp2Body)
	bp2ID, _ := bp2Body["id"].(string)

	resp := env.doRequest(t, "POST", "/admin/resources", map[string]any{
		"slug":                 "conflicting",
		"backend_kind":         "broker",
		"broker_provider_id":   bp2ID,
		"broker_provider_slug": "bp-one",
		"display_name":         "Conflicting",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 for conflicting refs", resp.StatusCode)
	}
}

func TestAdmin_Resources_Create_UnknownBrokerProviderSlug(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)

	resp := env.doRequest(t, "POST", "/admin/resources", map[string]any{
		"slug":                 "unknown-bp",
		"backend_kind":         "broker",
		"broker_provider_slug": "no-such-provider",
		"display_name":         "X",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		// resource_not_found surfaces from BrokerProviderAdminPort.GetBySlug.
		t.Fatalf("status %d, want 404 for unknown provider slug", resp.StatusCode)
	}
}
