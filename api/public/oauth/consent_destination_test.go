package oauth

import (
	"bytes"
	"strings"
	"testing"
)

// render is the consent template applied to page data, as the handler renders
// it. Asserting on the HTML is the point: what this requirement protects is
// what the user sees, not what the struct holds.
func renderConsent(t *testing.T, data consentPageData) string {
	t.Helper()
	var buf bytes.Buffer
	if err := consentTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("render consent: %v", err)
	}
	return buf.String()
}

// MCP-SEC-024: the destination host must be on the screen. It is the only part
// of the request the server verified — the client name beside it is
// self-declared, and with CIMD any host can publish a document claiming any
// name.
func TestConsentTemplate_ShowsRedirectHost(t *testing.T) {
	page := renderConsent(t, consentPageData{
		ClientName:   "Some Client",
		RedirectHost: "app.example.com",
	})
	if !strings.Contains(page, "app.example.com") {
		t.Error("the consent page does not show the redirect host")
	}
	if !strings.Contains(page, "send your authorization to") {
		t.Error("the destination is shown without saying what it is")
	}
}

// MCP-SEC-022: a loopback destination must be marked. Without it the screen for
// a local listener is byte-identical to one for a hosted app, which is exactly
// the impersonation the specification says a metadata document cannot prevent
// on its own.
func TestConsentTemplate_WarnsOnLoopbackDestination(t *testing.T) {
	local := renderConsent(t, consentPageData{
		ClientName:         "Some Client",
		RedirectHost:       "127.0.0.1:9999",
		RedirectIsLoopback: true,
	})
	hosted := renderConsent(t, consentPageData{
		ClientName:   "Some Client",
		RedirectHost: "app.example.com",
	})

	if !strings.Contains(local, "your own computer") {
		t.Error("a loopback destination carries no warning")
	}
	if strings.Contains(hosted, "your own computer") {
		t.Error("a hosted destination carries the loopback warning")
	}
	if local == hosted {
		t.Error("the loopback and hosted consent screens are identical")
	}
}

// A client name is attacker-chosen and unbounded, so it must not be able to
// impersonate the destination block or break out of its own element.
func TestConsentTemplate_ClientNameCannotForgeTheDestination(t *testing.T) {
	page := renderConsent(t, consentPageData{
		ClientName:   `<div class="host">app.example.com</div><script>alert(1)</script>`,
		RedirectHost: "evil.example",
	})
	if strings.Contains(page, "<script>") {
		t.Error("the client name was rendered as markup")
	}
	if strings.Contains(page, `<div class="host">app.example.com</div>`) {
		t.Error("the client name forged a destination block")
	}
	if !strings.Contains(page, "evil.example") {
		t.Error("the real destination is missing")
	}
}

// An unparseable or hostless redirect URI yields an empty host. Rendering an
// empty destination block would be worse than none: it asserts a destination
// and names nothing.
func TestConsentTemplate_OmitsEmptyDestination(t *testing.T) {
	page := renderConsent(t, consentPageData{ClientName: "Some Client"})
	if strings.Contains(page, "send your authorization to") {
		t.Error("an empty destination block was rendered")
	}
}
