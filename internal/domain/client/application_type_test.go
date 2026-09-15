package client

import "testing"

// The two values OpenID Connect Dynamic Client Registration 1.0 defines, plus
// empty for a request that omits the member. Anything else is refused: an AS
// that silently accepted "desktop" would store a value no consumer understands,
// and the client would believe it had declared something.
func TestValidateApplicationType(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"web", ApplicationTypeWeb, false},
		{"native", ApplicationTypeNative, false},
		{"omitted", "", false},
		{"unknown value", "desktop", true},
		{"wrong case", "Web", true},
		{"whitespace", " web", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateApplicationType(tc.value)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateApplicationType(%q) = nil, want an error", tc.value)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateApplicationType(%q) = %v, want nil", tc.value, err)
			}
		})
	}
}

// A client registered before the field existed has no stored value. Every
// consumer must see the OIDC default rather than an empty string, because
// "unset" and "web" mean the same thing everywhere except the audit trail.
func TestEffectiveApplicationType(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		stored string
		want   string
	}{
		{"empty resolves to the OIDC default", "", ApplicationTypeWeb},
		{"explicit web", ApplicationTypeWeb, ApplicationTypeWeb},
		{"native is preserved", ApplicationTypeNative, ApplicationTypeNative},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := &Client{ApplicationType: tc.stored}
			if got := c.EffectiveApplicationType(); got != tc.want {
				t.Errorf("EffectiveApplicationType() = %q, want %q", got, tc.want)
			}
			// The stored value itself must be left alone: the distinction
			// between "never declared" and an explicit "web" is what an
			// operator auditing intent relies on.
			if c.ApplicationType != tc.stored {
				t.Errorf("EffectiveApplicationType mutated the stored value to %q", c.ApplicationType)
			}
		})
	}
}
