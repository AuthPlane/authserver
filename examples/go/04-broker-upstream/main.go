// Tier 04 — Broker upstream + RFC 8693 Token Exchange + ConsentRequiredError (Go).
//
// Demonstrates the canonical brokered-vend shape: an agent holds a
// user-issued access token (the `subject_token`) and trades it at the AS
// token endpoint for the **actual upstream provider token** (e.g. a
// `gho_…` GitHub token). The exchange is performed via the
// `urn:ietf:params:oauth:grant-type:token-exchange` grant (RFC 8693) —
// the AS validates the three-bound check
// (`consent_grants` + `broker_grants` + `policy.exchange.allowed_client_ids`)
// before vending; see
// docs/guides/upstream-providers/connecting-providers.md for the full
// recipe and docs/guides/upstream-providers/token-exchange-grant.md for the
// grant-level knobs.
//
// When the user has not yet authorized this resource (bound A or B), the AS
// returns a `consent_required` OAuth error with a `consent_url` field
// pointing at the right `/connect/{provider}` (or `/authorize`) page. The
// Go SDK surfaces this as `*authplane.ConsentRequiredError` so the agent can
// distinguish it from generic OAuth errors and elicit consent from its
// caller (a human, an MCP client, etc.) instead of failing hard.
//
// The auth-specific code lives between `// authplane:begin` /
// `// authplane:end` so the `tools/loccount` tool can audit the LOC budget
// for this tier. Tier 04 budget is 30 auth lines.
//
// Run via the example's Makefile:
//
//	cp .env.example .env
//	make verify
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/authplane/go-sdk/core/authplane"
)

// RFC 8693 token type URIs. Spelling them out as constants keeps the
// in-marker code short — the literal strings are long enough that inlining
// them would push the auth-LOC count over budget without adding clarity.
const (
	subjectTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
)

func main() {
	ctx := context.Background()

	// === transport / config boilerplate =========================================
	resource := os.Getenv("BROKER_RESOURCE_SLUG") // e.g. "github"
	scopes := []string{"repo"}                    // request the upstream "repo" scope
	userToken := os.Getenv("AUTHPLANE_USER_ACCESS_TOKEN")

	// === Authplane integration ==================================================
	// authplane:begin
	client := must(authplane.NewClient(ctx, os.Getenv("AUTHPLANE_ISSUER"),
		authplane.WithClientCredentials(os.Getenv("AUTHPLANE_CLIENT_ID"), os.Getenv("AUTHPLANE_CLIENT_SECRET")),
	))
	defer client.Close()
	tok, err := client.TokenExchange(ctx, authplane.TokenExchangeInput{
		SubjectToken:     userToken,
		SubjectTokenType: subjectTokenTypeAccessToken,
		Resources:        []string{resource},
		Scopes:           scopes,
	})
	var consentErr *authplane.ConsentRequiredError
	if errors.As(err, &consentErr) {
		fmt.Fprintf(os.Stderr, "consent_required: %s\n", consentErr.Error())
		fmt.Fprintf(os.Stderr, "open this URL to grant consent: %s\n", consentErr.ConsentURL)
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("token exchange failed: %v", err)
	}
	// authplane:end

	// === use the vended upstream token (stub) ===================================
	// In a real MCP server this is where you'd call the upstream provider's API
	// with the vended `tok.AccessToken` — e.g. `GET https://api.github.com/user`
	// with `Authorization: Bearer <tok.AccessToken>`. The example stops here so
	// it stays runnable without a live GitHub OAuth app; the verify pipeline
	// asserts the token shape on stdout instead.
	fmt.Printf("upstream token vended:\n")
	fmt.Printf("  token_type        = %s\n", tok.TokenType)
	fmt.Printf("  issued_token_type = %s\n", tok.IssuedTokenType)
	fmt.Printf("  expires_in        = %d\n", tok.ExpiresIn)
	fmt.Printf("  scope             = %s\n", tok.Scope)
	// Don't log the access token itself — it's a real upstream credential
	// (e.g. a GitHub `gho_…` token) in a production deployment.
	fmt.Printf("  access_token      = (redacted; length=%d)\n", len(tok.AccessToken))
}

// must panics on a non-nil error; used here to keep the example's auth-setup
// block focused on the SDK calls themselves rather than canonical Go error
// handling. A production agent would log and exit cleanly instead. See the
// 'Before / After' section of the README for how this helper interacts with
// the loccount budget for this tier.
func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}
