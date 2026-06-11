//go:build e2e

package scenarios

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// TestFrontingCascade_ResourceDelete exercises the cascade
// design through the admin HTTP surface:
//
//   - DELETE /admin/resources/{id} on a resource with fronting-link
//     dependents must reject with 409 when ?cascade=true is omitted.
//     The 409 body lists the dependents so a UI can surface them
//     without a second round-trip.
//
//   - DELETE /admin/resources/{id}?cascade=true must delete the
//     resource AND every link that references it (both source-side
//     and target-side dependents). The cascade emits one audit row
//     per removed link with detail reason=resource_cascade.
//
// Both directions are exercised: the test runs the same sequence twice,
// once with the victim resource as a fronting source and once with the
// victim as a fronting target. the CascadeDeleteForResource walks
// ListForResource which returns both halves of the link table, so the
// two cases share an implementation but each is worth pinning lest a
// future "filter by source only" change silently break the target side.
func TestFrontingCascade_ResourceDelete(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI:      true,
		EnableTokenExchange: true,
	}, []string{"placeholder"})

	// Subtest 1: the victim is the SOURCE of two outbound links.
	t.Run("source_side_cascade", func(t *testing.T) {
		const (
			srcSlug = "fcc-src-victim"
			tgt1    = "fcc-src-tgt1"
			tgt2    = "fcc-src-tgt2"
		)
		seedResource(h, srcSlug, "https://"+srcSlug+".test", []string{"A", "B"})
		seedResource(h, tgt1, "https://"+tgt1+".test", []string{"AA", "BB"})
		seedResource(h, tgt2, "https://"+tgt2+".test", []string{"AAA", "BBB"})
		h.AdminCreateFrontingLink(e2e.CreateFrontingLinkSpec{
			Source:   srcSlug,
			Target:   tgt1,
			ScopeMap: map[string][]string{"A": {"AA"}},
		})
		h.AdminCreateFrontingLink(e2e.CreateFrontingLinkSpec{
			Source:   srcSlug,
			Target:   tgt2,
			ScopeMap: map[string][]string{"A": {"AAA"}, "B": {"BBB"}},
		})
		runCascadeAssertions(t, h, srcSlug, []string{tgt1, tgt2}, true /* victimIsSource */)
	})

	// Subtest 2: the victim is the TARGET of two inbound links.
	// Both inbound sources need their own client_id == slug per Option β
	// — but DELETE never exercises the runtime path so the client side
	// is unused; only the resource graph matters here.
	t.Run("target_side_cascade", func(t *testing.T) {
		const (
			tgtSlug = "fcc-tgt-victim"
			src1    = "fcc-tgt-src1"
			src2    = "fcc-tgt-src2"
		)
		seedResource(h, tgtSlug, "https://"+tgtSlug+".test", []string{"AA", "BB"})
		seedResource(h, src1, "https://"+src1+".test", []string{"A"})
		seedResource(h, src2, "https://"+src2+".test", []string{"B"})
		h.AdminCreateFrontingLink(e2e.CreateFrontingLinkSpec{
			Source:   src1,
			Target:   tgtSlug,
			ScopeMap: map[string][]string{"A": {"AA"}},
		})
		h.AdminCreateFrontingLink(e2e.CreateFrontingLinkSpec{
			Source:   src2,
			Target:   tgtSlug,
			ScopeMap: map[string][]string{"B": {"BB"}},
		})
		runCascadeAssertions(t, h, tgtSlug, []string{src1, src2}, false /* victimIsSource */)
	})
}

// runCascadeAssertions drives the four checks that define the
// contract for both source-side and target-side cascades:
//
//  1. DELETE without ?cascade=true returns 409 with a JSON body whose
//     `dependents` array names the blocking links.
//  2. The resource and links are unchanged after the 409.
//  3. DELETE with ?cascade=true returns 204; the resource is gone and
//     every dependent link is gone.
//  4. The cascade emits one fronting_link.deleted audit row per removed
//     link with reason=resource_cascade in the detail.
//
// peers is the slice of slugs the victim is linked to (targets when
// victimIsSource, sources when !victimIsSource). The function builds
// the appropriate /admin/fronting/{source}/{target} probe path for
// each peer.
func runCascadeAssertions(t *testing.T, h *e2e.TestHarness, victimSlug string, peers []string, victimIsSource bool) {
	t.Helper()

	victim := h.AdminGetResourceBySlug(victimSlug)
	if victim.ID == "" {
		t.Fatalf("victim %q has no admin id", victimSlug)
	}

	// 1. DELETE without cascade -> 409 with dependents listed.
	resp := h.AdminRequest("DELETE", "/admin/resources/"+victim.ID, nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("DELETE without cascade: status %d, want 409 (dependents block); body=%s",
			resp.StatusCode, string(body))
	}
	if !mentionsAllPeers(string(body), victimSlug, peers, victimIsSource) {
		t.Errorf("409 body must list every dependent link so a UI can render them; got %s", string(body))
	}

	// 2. Resource still exists, links still exist.
	if probe := h.AdminRequest("GET", "/admin/resources/"+victim.ID, nil); probe.StatusCode != http.StatusOK {
		probe.Body.Close()
		t.Errorf("post-409 GET resource: status = %d, want 200 (delete must be a no-op on conflict)", probe.StatusCode)
	} else {
		probe.Body.Close()
	}
	for _, peer := range peers {
		path := frontingPath(victimSlug, peer, victimIsSource)
		probe := h.AdminRequest("GET", path, nil)
		probe.Body.Close()
		if probe.StatusCode != http.StatusOK {
			t.Errorf("post-409 GET %s: status = %d, want 200 (link must survive blocked delete)", path, probe.StatusCode)
		}
	}

	// 3. DELETE with cascade -> 204; resource and links gone.
	cresp := h.AdminRequest("DELETE", "/admin/resources/"+victim.ID+"?cascade=true", nil)
	cbody, _ := io.ReadAll(cresp.Body)
	cresp.Body.Close()
	if cresp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE with cascade=true: status %d, want 204; body=%s", cresp.StatusCode, string(cbody))
	}

	if probe := h.AdminRequest("GET", "/admin/resources/"+victim.ID, nil); probe.StatusCode != http.StatusNotFound {
		probe.Body.Close()
		t.Errorf("post-cascade GET resource: status = %d, want 404 (resource must be gone)", probe.StatusCode)
	} else {
		probe.Body.Close()
	}
	for _, peer := range peers {
		path := frontingPath(victimSlug, peer, victimIsSource)
		probe := h.AdminRequest("GET", path, nil)
		probe.Body.Close()
		if probe.StatusCode != http.StatusNotFound {
			t.Errorf("post-cascade GET %s: status = %d, want 404 (link must be cascade-deleted atomically)",
				path, probe.StatusCode)
		}
	}

	// 4. Audit: one fronting_link.deleted per removed link, with the
	// reason=resource_cascade marker FrontingService.CascadeDeleteForResource
	// emits. We don't pin row count (test isolation across subtests is
	// imperfect) but every peer-pair must have at least one matching row.
	for _, peer := range peers {
		src, tgt := victimSlug, peer
		if !victimIsSource {
			src, tgt = peer, victimSlug
		}
		needle := fmt.Sprintf("source=%s target=%s reason=resource_cascade", src, tgt)
		if !auditDetailContainsAll(t, h, "fronting_link.deleted", needle) {
			t.Errorf("missing fronting_link.deleted audit row with %q", needle)
		}
	}
}

// seedResource registers a Mint resource through the admin surface with
// a single named scope per entry. The cascade test never drives the
// runtime path (no /oauth/token calls), so policy.exchange is unused and
// can stay empty.
func seedResource(h *e2e.TestHarness, slug, uri string, scopes []string) {
	scopeViews := make([]e2e.AdminScope, len(scopes))
	for i, s := range scopes {
		scopeViews[i] = e2e.AdminScope{Name: s}
	}
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:        slug,
		URI:         uri,
		BackendKind: "mint",
		DisplayName: slug,
		Scopes:      scopeViews,
	})
}

// frontingPath builds /admin/fronting/{source}/{target} given the
// victim slug and one of its peers. When the victim is the source the
// peer is the target and vice versa.
func frontingPath(victim, peer string, victimIsSource bool) string {
	if victimIsSource {
		return "/admin/fronting/" + victim + "/" + peer
	}
	return "/admin/fronting/" + peer + "/" + victim
}

// mentionsAllPeers asserts that every peer slug appears in the 409
// JSON body's dependents list. The body shape is the
// frontingLinkConflictResponse (api/admin/resources.go) so we walk the
// `dependents` slice rather than substring-match the raw body — that
// way a peer slug accidentally appearing in the human-readable detail
// can't false-positive the test.
func mentionsAllPeers(body, victim string, peers []string, victimIsSource bool) bool {
	var parsed struct {
		Dependents []map[string]any `json:"dependents"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return false
	}
	if len(parsed.Dependents) < len(peers) {
		return false
	}
	for _, peer := range peers {
		wantSrc, wantTgt := victim, peer
		if !victimIsSource {
			wantSrc, wantTgt = peer, victim
		}
		found := false
		for _, dep := range parsed.Dependents {
			src, _ := dep["source_slug"].(string)
			tgt, _ := dep["target_slug"].(string)
			if src == wantSrc && tgt == wantTgt {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	// Sanity: detail string should also mention "cascade" so an operator
	// reading the raw 409 has a hint how to recover.
	return strings.Contains(strings.ToLower(body), "cascade")
}
