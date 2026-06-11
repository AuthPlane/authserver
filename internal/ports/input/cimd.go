package input

import (
	"context"

	"github.com/authplane/authserver/internal/domain/client"
)

// CIMDPort handles Client ID Metadata Document verification (MCP spec).
// CIMD is pull-based: the AS fetches the client's metadata URL to auto-register.
type CIMDPort interface {
	// VerifyCIMD fetches and validates a Client ID Metadata Document.
	// If the client_id is a URL, this creates or updates the client from the document.
	VerifyCIMD(ctx context.Context, clientID string) (*client.Client, error)
}
