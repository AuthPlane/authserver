package client

import (
	"strings"
	"testing"
)

func TestValidateRedirectURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"valid https", "https://app.example.com/callback", false},
		{"valid https with port", "https://app.example.com:8443/callback", false},
		{"valid localhost http", "http://localhost:8080/callback", false},
		{"valid 127.0.0.1 http", "http://127.0.0.1:3000/callback", false},
		{"valid ipv6 localhost http", "http://[::1]:3000/callback", false},
		{"reject http non-localhost", "http://app.example.com/callback", true},
		{"reject fragment", "https://app.example.com/callback#frag", true},
		{"reject no scheme", "app.example.com/callback", true},
		{"reject ftp scheme", "ftp://app.example.com/callback", true},
		{"reject empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRedirectURI(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRedirectURI(%q) error = %v, wantErr %v", tt.uri, err, tt.wantErr)
			}
		})
	}
}

func TestValidateGrantType(t *testing.T) {
	if err := ValidateGrantType("authorization_code"); err != nil {
		t.Errorf("authorization_code should be valid: %v", err)
	}
	if err := ValidateGrantType("refresh_token"); err != nil {
		t.Errorf("refresh_token should be valid: %v", err)
	}
	if err := ValidateGrantType("client_credentials"); err != nil {
		t.Errorf("client_credentials should be valid: %v", err)
	}
	if err := ValidateGrantType("implicit"); err == nil {
		t.Error("implicit should be rejected")
	}
}

func TestValidateResponseType(t *testing.T) {
	if err := ValidateResponseType("code"); err != nil {
		t.Errorf("code should be valid: %v", err)
	}
	if err := ValidateResponseType("token"); err == nil {
		t.Error("token (implicit) should be rejected")
	}
}

func TestValidateAuthMethod(t *testing.T) {
	for _, m := range []string{"none", "client_secret_basic", "client_secret_post"} {
		if err := ValidateAuthMethod(m); err != nil {
			t.Errorf("%q should be valid: %v", m, err)
		}
	}
	if err := ValidateAuthMethod("private_key_jwt"); err == nil {
		t.Error("private_key_jwt should be rejected")
	}
}

func TestValidateCreateParamsValid(t *testing.T) {
	p := CreateParams{
		Name:         "My MCP Client",
		RedirectURIs: []string{"https://app.example.com/callback"},
	}
	p.Defaults()
	if err := ValidateCreateParams(p, nil); err != nil {
		t.Fatalf("valid params should pass: %v", err)
	}
}

func TestValidateCreateParamsMissingName(t *testing.T) {
	p := CreateParams{
		RedirectURIs: []string{"https://app.example.com/callback"},
	}
	p.Defaults()
	err := ValidateCreateParams(p, nil)
	if err == nil {
		t.Fatal("missing name should fail")
	}
	if !strings.Contains(err.Error(), "client_name") {
		t.Errorf("error should mention client_name: %v", err)
	}
}

func TestValidateCreateParamsEmptyName(t *testing.T) {
	p := CreateParams{
		Name:         "   ",
		RedirectURIs: []string{"https://app.example.com/callback"},
	}
	p.Defaults()
	if err := ValidateCreateParams(p, nil); err == nil {
		t.Error("whitespace-only name should fail")
	}
}

func TestValidateCreateParamsNoRedirectURIs(t *testing.T) {
	p := CreateParams{Name: "Test"}
	p.Defaults()
	err := ValidateCreateParams(p, nil)
	if err == nil {
		t.Fatal("missing redirect_uris should fail")
	}
	if !strings.Contains(err.Error(), "redirect_uri") {
		t.Errorf("error should mention redirect_uri: %v", err)
	}
}

// Matrix: 2.11 — upgraded from ⚠️: empty redirect_uris array must be rejected
func TestValidateCreateParamsEmptyRedirectURIs(t *testing.T) {
	p := CreateParams{
		Name:         "Test",
		RedirectURIs: []string{}, // empty array, not nil
	}
	p.Defaults()
	err := ValidateCreateParams(p, nil)
	if err == nil {
		t.Fatal("empty redirect_uris should fail")
	}
	if !strings.Contains(err.Error(), "redirect_uri") {
		t.Errorf("error should mention redirect_uri: %v", err)
	}
}

func TestValidateCreateParamsInvalidRedirectURI(t *testing.T) {
	p := CreateParams{
		Name:         "Test",
		RedirectURIs: []string{"http://evil.com/callback"},
	}
	p.Defaults()
	if err := ValidateCreateParams(p, nil); err == nil {
		t.Error("http non-localhost redirect should fail")
	}
}

func TestValidateCreateParamsInvalidGrantType(t *testing.T) {
	p := CreateParams{
		Name:         "Test",
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"implicit"},
	}
	if err := ValidateCreateParams(p, nil); err == nil {
		t.Error("implicit grant type should fail")
	}
}

func TestValidateCreateParamsLongName(t *testing.T) {
	p := CreateParams{
		Name:         strings.Repeat("a", maxClientNameLength+1),
		RedirectURIs: []string{"https://app.example.com/callback"},
	}
	p.Defaults()
	if err := ValidateCreateParams(p, nil); err == nil {
		t.Error("name exceeding max length should fail")
	}
}

// Matrix: 18.15 — Max redirect URIs enforced (10 max)
func TestValidateCreateParams_TooManyRedirectURIs(t *testing.T) {
	uris := make([]string, maxRedirectURIs+1)
	for i := range uris {
		uris[i] = "https://app.example.com/callback" + strings.Repeat("x", i)
	}
	p := CreateParams{
		Name:         "Too Many URIs",
		RedirectURIs: uris,
	}
	p.Defaults()
	err := ValidateCreateParams(p, nil)
	if err == nil {
		t.Fatalf("expected error for %d redirect_uris (max %d)", len(uris), maxRedirectURIs)
	}
	if !strings.Contains(err.Error(), "too many redirect_uris") {
		t.Errorf("error should mention too many redirect_uris: %v", err)
	}
}

// Matrix: 18.15 — Exactly max redirect URIs is allowed
func TestValidateCreateParams_ExactMaxRedirectURIs(t *testing.T) {
	uris := make([]string, maxRedirectURIs)
	for i := range uris {
		uris[i] = "https://app.example.com/callback" + strings.Repeat("x", i)
	}
	p := CreateParams{
		Name:         "Exact Max URIs",
		RedirectURIs: uris,
	}
	p.Defaults()
	if err := ValidateCreateParams(p, nil); err != nil {
		t.Errorf("exactly %d redirect_uris should be allowed: %v", maxRedirectURIs, err)
	}
}

// client_credentials-only clients don't need redirect_uris.
func TestValidateCreateParams_ClientCredentialsNoRedirectURI(t *testing.T) {
	p := CreateParams{
		Name:                    "Machine Client",
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	p.Defaults()
	if err := ValidateCreateParams(p, nil); err != nil {
		t.Errorf("client_credentials-only should not require redirect_uris: %v", err)
	}
}

// token-exchange-only clients don't need redirect_uris.
func TestValidateCreateParams_TokenExchangeNoRedirectURI(t *testing.T) {
	p := CreateParams{
		Name:                    "Exchange Client",
		GrantTypes:              []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	p.Defaults()
	if err := ValidateCreateParams(p, nil); err != nil {
		t.Errorf("token-exchange-only should not require redirect_uris: %v", err)
	}
}

// mixed grant types with auth_code still require redirect_uri.
func TestValidateCreateParams_MixedGrantTypesRequiresRedirectURI(t *testing.T) {
	p := CreateParams{
		Name:       "Mixed Client",
		GrantTypes: []string{"authorization_code", "client_credentials"},
	}
	p.Defaults()
	err := ValidateCreateParams(p, nil)
	if err == nil {
		t.Fatal("mixed grant types with auth_code should require redirect_uris")
	}
	if !strings.Contains(err.Error(), "redirect_uri") {
		t.Errorf("error should mention redirect_uri: %v", err)
	}
}

func TestValidateCreateParamsMultipleErrors(t *testing.T) {
	p := CreateParams{} // missing everything
	p.Defaults()
	err := ValidateCreateParams(p, nil)
	if err == nil {
		t.Fatal("should fail with multiple errors")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if len(ve.Errors) < 2 {
		t.Errorf("expected multiple errors, got %d", len(ve.Errors))
	}
}

// a grant type that the AS isn't configured to honor must be
// rejected at registration time, with the error naming the env var the
// operator must flip. Without this guard, a status=active client would
// reach /oauth/token and only fail there with unsupported_grant_type.
func TestValidateCreateParams_GrantNotEnabled_ClientCredentials(t *testing.T) {
	p := CreateParams{
		Name:                    "CC Client",
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	p.Defaults()

	enabled := []string{"authorization_code", "refresh_token"}
	err := ValidateCreateParams(p, enabled)
	if err == nil {
		t.Fatal("client_credentials should be rejected when not in enabledGrants")
	}
	if !strings.Contains(err.Error(), "client_credentials") {
		t.Errorf("error should name the offending grant: %v", err)
	}
	if !strings.Contains(err.Error(), "AUTHPLANE_CLIENT_CREDENTIALS_ENABLED") {
		t.Errorf("error should name the env var that enables the grant: %v", err)
	}
}

func TestValidateCreateParams_GrantNotEnabled_TokenExchange(t *testing.T) {
	p := CreateParams{
		Name:                    "TE Client",
		GrantTypes:              []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	p.Defaults()

	err := ValidateCreateParams(p, []string{"authorization_code", "refresh_token"})
	if err == nil {
		t.Fatal("token-exchange should be rejected when not in enabledGrants")
	}
	if !strings.Contains(err.Error(), "AUTHPLANE_TOKEN_EXCHANGE_ENABLED") {
		t.Errorf("error should name the env var: %v", err)
	}
}

func TestValidateCreateParams_GrantEnabled_Accepted(t *testing.T) {
	p := CreateParams{
		Name:                    "CC Client",
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	p.Defaults()

	enabled := []string{"authorization_code", "refresh_token", "client_credentials"}
	if err := ValidateCreateParams(p, enabled); err != nil {
		t.Errorf("client_credentials should pass when in enabledGrants: %v", err)
	}
}

// ValidateGrantTypesEnabled is the standalone helper used by the
// CIMD ingest path (and any future client-creation seam). Round-trip the
// same matrix the in-validator check exercises, but through the public
// helper so callers other than ValidateCreateParams stay covered too.
func TestValidateGrantTypesEnabled(t *testing.T) {
	t.Run("nil enabledGrants skips the check", func(t *testing.T) {
		if err := ValidateGrantTypesEnabled([]string{"client_credentials"}, nil); err != nil {
			t.Errorf("nil enabledGrants must skip enforcement: %v", err)
		}
	})

	t.Run("disabled grant rejected with env var name", func(t *testing.T) {
		err := ValidateGrantTypesEnabled(
			[]string{"client_credentials"},
			[]string{"authorization_code", "refresh_token"},
		)
		if err == nil {
			t.Fatal("client_credentials must be rejected")
		}
		if !strings.Contains(err.Error(), "AUTHPLANE_CLIENT_CREDENTIALS_ENABLED") {
			t.Errorf("error should name the env var: %v", err)
		}
	})

	t.Run("enabled grant accepted", func(t *testing.T) {
		err := ValidateGrantTypesEnabled(
			[]string{"client_credentials"},
			[]string{"authorization_code", "refresh_token", "client_credentials"},
		)
		if err != nil {
			t.Errorf("enabled grant must pass: %v", err)
		}
	})

	t.Run("syntactically-bad grant skipped (handled elsewhere)", func(t *testing.T) {
		// "implicit" is not a recognized grant string — ValidateGrantType
		// surfaces that elsewhere; the enabled-set check should not
		// double-report on it.
		err := ValidateGrantTypesEnabled(
			[]string{"implicit"},
			[]string{"authorization_code"},
		)
		if err != nil {
			t.Errorf("syntactically-bad grant should be skipped here: %v", err)
		}
	})
}

// when enabledGrants is nil, the new check is skipped — used by
// tests/legacy callers that don't have a full Config. Production wiring
// always passes a populated set.
func TestValidateCreateParams_NilEnabledGrants_SkipsCheck(t *testing.T) {
	p := CreateParams{
		Name:                    "CC Client",
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	p.Defaults()

	if err := ValidateCreateParams(p, nil); err != nil {
		t.Errorf("nil enabledGrants should skip the runtime-enabled check: %v", err)
	}
}
