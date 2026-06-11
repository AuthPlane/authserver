package services

// ResourceLister provides runtime access to configured resources. It is the
// shared seam consumed by every grant-emitting service (token, authorize,
// consent, client_credentials, jwt_bearer, token_exchange). Implementations
// today are *ResourceRegistry (production / e2e harness) and
// StaticResourceLister (unit tests).
type ResourceLister interface {
	List() []ResourceInfo
}

// StaticResourceLister wraps a fixed slice of ResourceInfo. Used by unit
// tests that exercise scope-validation paths without needing a live
// ResourceStore.
type StaticResourceLister struct {
	resources []ResourceInfo
}

// NewStaticResourceLister creates a lister backed by a static slice.
func NewStaticResourceLister(resources []ResourceInfo) *StaticResourceLister {
	return &StaticResourceLister{resources: resources}
}

// List returns the static resource list.
func (s *StaticResourceLister) List() []ResourceInfo {
	return s.resources
}
