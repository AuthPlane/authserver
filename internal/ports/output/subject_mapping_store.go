package output

import (
	"context"

	"github.com/authplane/authserver/internal/domain/xaa"
)

// SubjectMappingStore persists XAA subject mappings between
// external IdP subjects and local user identities.
type SubjectMappingStore interface {
	// Save creates or updates a subject mapping.
	Save(ctx context.Context, m xaa.SubjectMapping) error

	// GetMapping retrieves the mapping for a specific IdP and subject.
	GetMapping(ctx context.Context, idpID, idpSubject string) (*xaa.SubjectMapping, error)

	// ListByIDP returns all mappings for a given trusted IdP.
	ListByIDP(ctx context.Context, idpID string) ([]xaa.SubjectMapping, error)

	// Delete removes a mapping by ID.
	Delete(ctx context.Context, id string) error
}
