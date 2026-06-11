package idp

import (
	"testing"
)

func TestTrustedIDP_Validate(t *testing.T) {
	valid := TrustedIDP{
		Name:     "Test IdP",
		Issuer:   "https://idp.example.com",
		JWKSUri:  "https://idp.example.com/.well-known/jwks.json",
		Audience: "https://authplane.example.com",
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}

	tests := []struct {
		name    string
		modify  func(*TrustedIDP)
		wantErr string
	}{
		{"empty name", func(i *TrustedIDP) { i.Name = "" }, "name is required"},
		{"empty issuer", func(i *TrustedIDP) { i.Issuer = "" }, "issuer is required"},
		{"http issuer", func(i *TrustedIDP) { i.Issuer = "http://idp.example.com" }, "issuer must use HTTPS"},
		{"invalid issuer", func(i *TrustedIDP) { i.Issuer = "://bad" }, "issuer is not a valid URL"},
		{"http jwks_uri", func(i *TrustedIDP) { i.JWKSUri = "http://idp.example.com/jwks" }, "jwks_uri must use HTTPS"},
		{"empty audience", func(i *TrustedIDP) { i.Audience = "" }, "audience is required"},
		{"empty jwks_uri ok", func(i *TrustedIDP) { i.JWKSUri = "" }, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := valid // copy
			tt.modify(&idp)
			err := idp.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if got := err.Error(); !contains(got, tt.wantErr) {
				t.Fatalf("expected error containing %q, got: %q", tt.wantErr, got)
			}
		})
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
