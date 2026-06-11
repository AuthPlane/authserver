package input

import (
	"context"

	"github.com/authplane/authserver/internal/domain/xaa"
)

// SubjectMappingPort provides administrative CRUD for XAA subject mappings.
type SubjectMappingPort interface {
	CreateMapping(ctx context.Context, req CreateMappingRequest) (*xaa.SubjectMapping, error)
	ListMappings(ctx context.Context, idpID string) ([]xaa.SubjectMapping, error)
	DeleteMapping(ctx context.Context, id string) error
}

// CreateMappingRequest is the input for creating a subject mapping.
type CreateMappingRequest struct {
	IDPID       string `json:"idp_id"`
	IDPSubject  string `json:"idp_subject"`
	LocalUserID string `json:"local_user_id,omitempty"`
}
