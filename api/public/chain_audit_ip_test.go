package public

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
)

type capturingAuditStore struct{ events []audit.Event }

func (c *capturingAuditStore) Record(_ context.Context, e *audit.Event) error {
	c.events = append(c.events, *e)
	return nil
}

func (c *capturingAuditStore) Query(context.Context, output.AuditFilter) ([]audit.Event, error) {
	return nil, nil
}

// An event recorded while serving a request through the chain carries the
// connection's address, even though the emit site left IP empty.
func TestDefaultChain_AuditEventCarriesClientIP(t *testing.T) {
	deps := testChainDeps()
	store := &capturingAuditStore{}
	auditor := services.NewAuditService(store, deps.Obs)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auditor.Record(r.Context(), audit.NewEvent(audit.ActionTokenIssued, "user-1", "client-1", "", ""))
		w.WriteHeader(http.StatusOK)
	})

	req := corsRequest()
	req.RemoteAddr = "198.51.100.23:51000"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	DefaultChain(deps, inner).ServeHTTP(httptest.NewRecorder(), req)

	if len(store.events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(store.events))
	}
	if got := store.events[0].IP; got != "198.51.100.23" {
		t.Fatalf("IP = %q, want the RemoteAddr host 198.51.100.23", got)
	}
}
