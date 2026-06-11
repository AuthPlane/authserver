package resource

import (
	"sort"
	"time"

	"github.com/authplane/authserver/internal/domain"
)

// FrontingLink declares that a Mint Resource (Source) may exchange tokens for
// a downstream Resource (Target) via RFC 8693 token-exchange, translating
// scopes per ScopeMap. Operator-declared; the runtime path that consumes these
// rows lands in (Inc N+1). See / and the architecture doc
// §gateway-fan-out.
//
// Fronting is a top-level concept, NOT nested under mint:/broker: blocks; the
// fronting_links table is the source of truth and Resource records carry no
// fronting fields.
type FrontingLink struct {
	SourceSlug string
	TargetSlug string
	ScopeMap   ScopeMap
	CreatedAt  time.Time
	CreatedBy  string
}

// ScopeMap encodes the 1:N source-scope → target-scope mapping. An empty
// value list is rejected by Validate; mappings always carry at least one
// target scope per source scope. JSON shape: { "src1": ["dst1","dst2"], ... }.
type ScopeMap map[string][]string

// SourceScopes returns the keys (source-side scopes) in deterministic order.
// Used by edit-time validation in FrontingService and by the Admin UI.
func (m ScopeMap) SourceScopes() []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TargetScopes returns the union of target scopes across every entry, in
// deterministic order with duplicates removed.
func (m ScopeMap) TargetScopes() []string {
	seen := make(map[string]struct{})
	for _, vs := range m {
		for _, v := range vs {
			seen[v] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ReferencesSourceScope reports whether scope appears as a key.
func (m ScopeMap) ReferencesSourceScope(scope string) bool {
	_, ok := m[scope]
	return ok
}

// ReferencesTargetScope reports whether scope appears as a value anywhere.
func (m ScopeMap) ReferencesTargetScope(scope string) bool {
	for _, vs := range m {
		for _, v := range vs {
			if v == scope {
				return true
			}
		}
	}
	return false
}

// Validate enforces shape-only invariants on the link itself: slugs present
// and well-formed, scope_map non-empty with non-empty entries, no duplicate
// targets within a single source's value list. Cross-Resource semantics
// (kind, scope-membership, cycle detection) live in FrontingService, which
// can consult the resource registry; they have no place here.
func (l *FrontingLink) Validate() error {
	if l.SourceSlug == "" {
		return domain.NewInvalidRequestError("source slug is required")
	}
	if l.TargetSlug == "" {
		return domain.NewInvalidRequestError("target slug is required")
	}
	if !slugPattern.MatchString(l.SourceSlug) {
		return domain.NewInvalidRequestError("source slug is malformed")
	}
	if !slugPattern.MatchString(l.TargetSlug) {
		return domain.NewInvalidRequestError("target slug is malformed")
	}
	if l.SourceSlug == l.TargetSlug {
		return domain.NewInvalidRequestError("source and target must differ (no self-loop)")
	}
	if len(l.ScopeMap) == 0 {
		return domain.NewInvalidRequestError("scope_map must contain at least one entry")
	}
	for src, tgts := range l.ScopeMap {
		if src == "" {
			return domain.NewInvalidRequestError("scope_map keys must not be empty")
		}
		if len(tgts) == 0 {
			return domain.NewInvalidRequestError("scope_map entry " + src + " must list at least one target scope")
		}
		seen := make(map[string]struct{}, len(tgts))
		for _, t := range tgts {
			if t == "" {
				return domain.NewInvalidRequestError("scope_map entry " + src + " contains an empty target scope")
			}
			if _, dup := seen[t]; dup {
				return domain.NewInvalidRequestError("scope_map entry " + src + " contains duplicate target scope " + t)
			}
			seen[t] = struct{}{}
		}
	}
	return nil
}
