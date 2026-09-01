package oauth

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
)

// Templates render the resolved action/link URL (FormAction / LoginURL) that
// the handler computes via the URLBuilder: the path itself at the root, the
// mounted path behind a reverse proxy. The template never concatenates.
func TestTemplates_ResolvedURLs(t *testing.T) {
	cases := []struct {
		name         string
		tmpl         *template.Template
		data         any
		wantContains string
	}{
		{"login root", loginTmpl, loginPageData{ShowLocalLogin: true, FormAction: "/login"}, `action="/login"`},
		{"login mount", loginTmpl, loginPageData{ShowLocalLogin: true, FormAction: "/api/v2/auth/login"}, `action="/api/v2/auth/login"`},
		{"consent root", consentTmpl, consentPageData{FormAction: "/consent"}, `action="/consent"`},
		{"consent mount", consentTmpl, consentPageData{FormAction: "/api/v2/auth/consent"}, `action="/api/v2/auth/consent"`},
		{"oidc error root", oidcErrorTmpl, oidcErrorData{Error: "x", LoginURL: "/login"}, `href="/login"`},
		{"oidc error mount", oidcErrorTmpl, oidcErrorData{Error: "x", LoginURL: "/api/v2/auth/login"}, `href="/api/v2/auth/login"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.tmpl.Execute(&buf, tc.data); err != nil {
				t.Fatalf("execute: %v", err)
			}
			if !strings.Contains(buf.String(), tc.wantContains) {
				t.Errorf("rendered output missing %q", tc.wantContains)
			}
		})
	}
}
