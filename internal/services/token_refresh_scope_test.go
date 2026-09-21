package services

import (
	"errors"
	"testing"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
)

// Every branch of refreshScope, without a database. The family is what
// the user consented to; the ceiling is the client as it stands now.
func TestRefreshScope(t *testing.T) {
	cases := []struct {
		name      string
		requested string
		family    string
		ceiling   string
		want      string
		wantErr   error // nil = success; domain.ErrInvalidScope = refused
	}{
		// No ceiling: the family decides, as before.
		{"no ceiling, omitted", "", "a b", "", "a b", nil},
		{"no ceiling, narrower", "a", "a b", "", "a", nil},
		{"no ceiling, wider", "a b c", "a b", "", "", domain.ErrInvalidScope},
		{"no ceiling, disjoint", "z", "a b", "", "", domain.ErrInvalidScope},

		// Ceiling covers the family: nothing changes.
		{"covering ceiling, omitted echoes family verbatim", "", "b a", "a b c", "b a", nil},
		{"covering ceiling, narrower", "a", "a b", "a b", "a", nil},
		{"covering ceiling, wider than family", "a b c", "a b", "a b c", "", domain.ErrInvalidScope},

		// Ceiling cuts the family.
		{"cut ceiling, omitted narrows", "", "a b", "a", "a", nil},
		{"cut ceiling, explicit inside both", "a", "a b", "a", "a", nil},
		{"cut ceiling, explicit inside family outside ceiling", "a b", "a b", "a", "", domain.ErrInvalidScope},
		{"cut ceiling, explicit outside family", "c", "a b", "c", "", domain.ErrInvalidScope},

		// Ceiling and family disjoint.
		{"disjoint, omitted refused not empty token", "", "a b", "z", "", domain.ErrInvalidScope},
		{"disjoint, explicit refused", "a", "a b", "z", "", domain.ErrInvalidScope},

		// Set semantics.
		{"duplicates and order in request", "b a b", "a b", "a b", "a b", nil},
		{"whitespace in ceiling", "", "a b", "  b   a  ", "a b", nil},

		// An empty family (a token issued with no scope) stays empty.
		{"empty family, omitted", "", "", "a", "", nil},
		{"empty family, explicit refused by family", "a", "", "a", "", domain.ErrInvalidScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &client.Client{ID: "c", Scope: tc.ceiling, RegistrationSource: client.SourceAdmin}
			got, err := refreshScope(tc.requested, tc.family, c)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("scope = %q, want %q", got, tc.want)
			}
		})
	}
}

// A refusal by the ceiling names the ceiling; a refusal by the family is
// the bare invalid_scope. The description travels to the wire as
// error_description, so the two must be told apart.
func TestRefreshScope_DenialNamesTheCeiling(t *testing.T) {
	c := &client.Client{ID: "c", Scope: "a", RegistrationSource: client.SourceAdmin}
	_, byCeiling := refreshScope("a b", "a b", c)
	_, byFamily := refreshScope("a b c", "a b", c)
	if byCeiling == nil || byFamily == nil {
		t.Fatal("both should be refused")
	}
	if byCeiling.Error() == byFamily.Error() {
		t.Errorf("ceiling and family refusals read the same: %q", byCeiling)
	}
	if byCeiling.Error() == domain.ErrInvalidScope.Error() {
		t.Errorf("ceiling refusal carries no explanation: %q", byCeiling)
	}
}
