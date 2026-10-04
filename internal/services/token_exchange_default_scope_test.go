package services

import (
	"reflect"
	"testing"

	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/domain/scope"
)

// A direct Mint exchange that omits scope gets what an explicit request could
// have named on the branch that authorized it, and nothing when that is empty.
func TestDirectMintDefaultScopes(t *testing.T) {
	target := &resource.Resource{Scopes: []resource.Scope{{Name: "tasks.read"}, {Name: "tasks.write"}}}
	grant := func(s ...string) *resource.ConsentGrant { return &resource.ConsentGrant{Scopes: s} }
	cases := []struct {
		name    string
		grant   *resource.ConsentGrant
		subject string
		want    []string
	}{
		{"consent: identity-only subject takes the consented catalog scopes", grant("tasks.read", "tasks.write"), "", []string{"tasks.read", "tasks.write"}},
		{"consent: narrowed to the subject", grant("tasks.read", "tasks.write"), "tasks.write other", []string{"tasks.write"}},
		{"consent: consented beyond the catalog is dropped", grant("tasks.read", "tasks.admin"), "", []string{"tasks.read"}},
		{"consent: subject and consent disjoint", grant("tasks.read"), "tasks.write", nil},
		{"consent: empty grant", grant(), "tasks.read", nil},
		{"self-exchange: subject scopes the target declares", nil, "tasks.read other", []string{"tasks.read"}},
		{"self-exchange: identity-only subject derives nothing", nil, "", nil},
		{"self-exchange: subject holds nothing the target declares", nil, "other", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := directMintDefaultScopes(tc.grant, target, scope.Parse(tc.subject)); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
