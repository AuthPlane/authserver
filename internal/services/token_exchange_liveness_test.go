package services

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	clientdom "github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/domain/scope"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/output"
)

type livenessUserStore struct {
	output.UserStore
	byID map[string]*user.User
	err  error
}

func (s livenessUserStore) GetByID(_ context.Context, id string) (*user.User, error) {
	if s.err != nil {
		return nil, s.err
	}
	u, ok := s.byID[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}

// Disabling a user or suspending a client revokes nothing, so token exchange
// must refuse a subject token introspection already reports inactive. A
// fronted token's client_id is a resource slug and its sub may be a machine
// client; identities that do not resolve are not refused.
func TestTokenExchange_CheckLiveness(t *testing.T) {
	clients := newFakeClientStore()
	ctx := context.Background()
	for id, st := range map[string]clientdom.Status{
		"agent-active":    clientdom.StatusActive,
		"agent-suspended": clientdom.StatusSuspended,
		"agent-revoked":   clientdom.StatusRevoked,
	} {
		if err := clients.Create(ctx, &clientdom.Client{ID: id, Status: st}); err != nil {
			t.Fatal(err)
		}
	}
	users := livenessUserStore{byID: map[string]*user.User{
		"alice": {ID: "alice", Status: user.StatusActive},
		"bob":   {ID: "bob", Status: user.StatusDisabled},
	}}
	svc := &TokenExchangeService{clients: clients, users: users, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	cases := []struct {
		name       string
		sub, cid   string
		wantReason string
	}{
		{"active user, active client", "alice", "agent-active", ""},
		{"disabled user", "bob", "agent-active", "subject_inactive"},
		{"suspended issuing client", "alice", "agent-suspended", "issuing_client_inactive"},
		{"revoked issuing client", "alice", "agent-revoked", "issuing_client_inactive"},
		{"machine token, suspended client", "agent-suspended", "agent-suspended", "issuing_client_inactive"},
		{"machine token, active client", "agent-active", "agent-active", ""},
		{"fronted token: slug client_id, active user", "alice", "mcp-gw", ""},
		{"fronted token: slug client_id, disabled user", "bob", "mcp-gw", "subject_inactive"},
		{"fronted token: slug client_id, suspended machine subject", "agent-suspended", "mcp-gw", "subject_inactive"},
		{"fronted token: slug client_id, active machine subject", "agent-active", "mcp-gw", ""},
		{"unknown subject and client", "nobody", "nothing", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, err := svc.checkLiveness(ctx, noopSpan(), &crypto.AccessTokenClaims{Subject: tc.sub, ClientID: tc.cid})
			if tc.wantReason == "" {
				if err != nil {
					t.Fatalf("refused (%s): %v", reason, err)
				}
				return
			}
			if !errors.Is(err, domain.ErrInvalidGrant) || reason != tc.wantReason {
				t.Fatalf("got reason=%q err=%v, want %q / invalid_grant", reason, err, tc.wantReason)
			}
		})
	}

	t.Run("user store failure refuses as a fault", func(t *testing.T) {
		broken := &TokenExchangeService{clients: clients, users: livenessUserStore{err: errors.New("db down")}, logger: svc.logger}
		reason, err := broken.checkLiveness(ctx, noopSpan(), &crypto.AccessTokenClaims{Subject: "alice", ClientID: "agent-active"})
		if err == nil || errors.Is(err, domain.ErrInvalidGrant) || reason != "" {
			t.Fatalf("got reason=%q err=%v, want a non-grant fault", reason, err)
		}
	})
}

// A direct broker exchange that omits scope gets what an explicit request
// could have named — the attested scopes this resource declares, narrowed to
// the subject's scopes when it has any — and nothing when that set is empty.
func TestDirectBrokerDefaultScopes(t *testing.T) {
	target := &resource.Resource{Scopes: []resource.Scope{{Name: "tool:list"}, {Name: "tool:create"}}}
	cases := []struct {
		name     string
		attested []string
		subject  string
		want     []string
	}{
		{"attested and declared", []string{"tool:list"}, "", []string{"tool:list"}},
		{"attested beyond the catalog is dropped", []string{"tool:list", "tool:delete"}, "", []string{"tool:list"}},
		{"narrowed to the subject", []string{"tool:list", "tool:create"}, "tool:create", []string{"tool:create"}},
		{"subject holds none of the attested scopes", []string{"tool:list"}, "tool:create", nil},
		{"attestation covers nothing declared", []string{"tool:delete"}, "", nil},
		{"empty attestation", nil, "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := directBrokerDefaultScopes(&resource.ConsentGrant{Scopes: tc.attested}, target, scope.Parse(tc.subject))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
	if got := directBrokerDefaultScopes(nil, target, scope.Parse("")); got != nil {
		t.Errorf("nil attestation: got %v, want nil", got)
	}
}
