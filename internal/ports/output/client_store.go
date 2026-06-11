// Package output defines the driven ports — what the system needs from the outside world.
package output

import (
	"context"

	"github.com/authplane/authserver/internal/domain/client"
)

// ClientStore persists and retrieves OAuth clients.
type ClientStore interface {
	// Create stores a new client. The client's ID must already be set.
	Create(ctx context.Context, c *client.Client) error

	// GetByID returns a client by its client_id.
	GetByID(ctx context.Context, id string) (*client.Client, error)

	// GetByCIMDURL returns a client registered via CIMD with the given URL.
	GetByCIMDURL(ctx context.Context, url string) (*client.Client, error)

	// Update persists changes to an existing client.
	Update(ctx context.Context, c *client.Client) error

	// List returns clients matching the filter.
	List(ctx context.Context, status string, source string, limit, offset int) ([]client.Client, error)

	// Count returns the total number of clients, optionally filtered by status.
	Count(ctx context.Context, status string) (int, error)

	// ListAgents returns all active clients where is_agent=true.
	ListAgents(ctx context.Context) ([]client.Client, error)

	// Delete permanently removes a client by ID.
	Delete(ctx context.Context, id string) error
}
