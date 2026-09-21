package services

import (
	"slices"
	"testing"

	"github.com/authplane/authserver/internal/domain/client"
)

// TestEveryGrantTypeIsClassified is the guard on isDelegatedOnly's default.
//
// isDelegatedOnly asks whether any machine grant is present, so a grant nobody
// classified counts as delegated and its self-registered clients are handed
// oauth.default_client_scope. That is the right answer for a delegated grant
// (device_code, say) and a privilege escalation for a machine one: those grants
// issue tokens with no user and no consent, so the ceiling is the only bound.
//
// Neither default is right for every future grant, so this asserts the
// classification is written down rather than inherited. Adding a grant to
// client.ValidGrantTypes fails here until it is placed in machineGrants or
// delegatedGrants — a decision for whoever adds it and knows which it is.
func TestEveryGrantTypeIsClassified(t *testing.T) {
	for _, gt := range client.ValidGrantTypes() {
		machine := slices.Contains(machineGrants, gt)
		delegated := slices.Contains(delegatedGrants, gt)

		switch {
		case machine && delegated:
			t.Errorf("grant %q is in both machineGrants and delegatedGrants; it "+
				"must be exactly one", gt)
		case !machine && !delegated:
			t.Errorf("grant %q is accepted by client.ValidGrantTypes but "+
				"classified in neither machineGrants nor delegatedGrants. Decide "+
				"which it is: does a user approve at an authorization endpoint "+
				"before a token is issued? If yes it is delegated and its "+
				"self-registered clients get oauth.default_client_scope; if no it "+
				"is a machine grant and they must get no ceiling at all.", gt)
		}
	}
}

// TestClassifiedGrantsAreValid catches the reverse drift: a grant removed from
// or renamed in client.ValidGrantTypes while a stale entry lingers here, which
// would leave isDelegatedOnly testing for a grant no client can hold.
func TestClassifiedGrantsAreValid(t *testing.T) {
	valid := client.ValidGrantTypes()
	for _, gt := range slices.Concat(machineGrants, delegatedGrants) {
		if !slices.Contains(valid, gt) {
			t.Errorf("grant %q is classified here but is not in "+
				"client.ValidGrantTypes; remove it or restore the grant", gt)
		}
	}
}

// TestIsDelegatedOnly pins the classification's effect, including the mixed
// case: one machine grant makes the whole client machine, because Scope is a
// single field and a ceiling granted for the delegated path would be just as
// spendable on the machine one.
func TestIsDelegatedOnly(t *testing.T) {
	tests := []struct {
		name       string
		grantTypes []string
		want       bool
	}{
		{"delegated only", []string{"authorization_code", "refresh_token"}, true},
		{"machine only", []string{"client_credentials"}, false},
		{"mixed counts as machine", []string{"authorization_code", "client_credentials"}, false},
		{"jwt-bearer", []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"}, false},
		{"token-exchange", []string{"urn:ietf:params:oauth:grant-type:token-exchange"}, false},
		{"empty", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDelegatedOnly(tt.grantTypes); got != tt.want {
				t.Errorf("isDelegatedOnly(%v) = %v, want %v", tt.grantTypes, got, tt.want)
			}
		})
	}
}
