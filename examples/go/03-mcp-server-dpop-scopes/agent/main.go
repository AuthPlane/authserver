// Tier 03 — DPoP-bound agent with per-tool scope (Go).
//
// Acquires a DPoP-bound (RFC 9449) access token from the AS using the
// `client_credentials` grant, then calls the tier-03 MCP server's two
// scoped tools (`echo` requires `mcp:echo`, `add_numbers` requires
// `mcp:add`). Every outbound request carries:
//
//   - `Authorization: DPoP <access_token>` — the access token whose
//     `cnf.jkt` claim binds it to this agent's DPoP key.
//   - `DPoP: <proof>` — a fresh per-request proof JWT signed with that key,
//     covering the HTTP method + URL + access-token hash (`ath`).
//
// A stolen access token alone is therefore useless: without the DPoP
// private key, an attacker cannot mint a valid proof.
//
// The auth-specific code lives between `// authplane:begin` /
// `// authplane:end` so the `tools/loccount` tool can audit the LOC
// budget for this tier.
//
// Run via the example's Makefile:
//
//	cp .env.example .env
//	make verify
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/go-jose/go-jose/v4"
)

func main() {
	ctx := context.Background()

	// === transport / HTTP client boilerplate =====================================
	mcpURL := os.Getenv("MCP_URL")
	resource := os.Getenv("AUTHPLANE_RESOURCE")

	// === Authplane integration =================================================
	// authplane:begin
	km := must(authplane.NewDPoPKeyMaterial(jose.ES256))
	client := must(authplane.NewClient(ctx, os.Getenv("AUTHPLANE_ISSUER"),
		authplane.WithClientCredentials(os.Getenv("AUTHPLANE_CLIENT_ID"), os.Getenv("AUTHPLANE_CLIENT_SECRET")),
		authplane.WithDPoP(km)))
	defer client.Close()
	tok := must(client.ClientCredentials(ctx, []string{"mcp:echo", "mcp:add"}, []string{resource}))
	signer := client.DPoPSigner()
	// authplane:end

	// === call both MCP tools ====================================================
	// echo — requires scope mcp:echo
	echoBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello from tier-03 agent"}}}`)
	if out, err := callMCP(ctx, mcpURL, tok.AccessToken, signer, echoBody); err != nil {
		log.Fatalf("echo call failed: %v", err)
	} else {
		fmt.Printf("echo: %s\n", out)
	}

	// add_numbers — requires scope mcp:add
	addBody := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"add_numbers","arguments":{"a":2,"b":3}}}`)
	if out, err := callMCP(ctx, mcpURL, tok.AccessToken, signer, addBody); err != nil {
		log.Fatalf("add_numbers call failed: %v", err)
	} else {
		fmt.Printf("add_numbers: %s\n", out)
	}
}

// callMCP POSTs a JSON-RPC body to the MCP server with a freshly generated
// DPoP proof. Per RFC 9449 §7.1 the access token is sent under the `DPoP`
// authorization scheme (not `Bearer`) when it is sender-constrained, and the
// proof JWT goes in the separate `DPoP` request header. The proof binds to
// the access token via the `ath` claim, so even a passive observer who
// captures the token cannot replay it without also holding the private key.
func callMCP(ctx context.Context, url, accessToken string, signer *authplane.DPoPSigner, body []byte) (string, error) {
	// authplane:begin
	proof := must(signer.GenerateProof(http.MethodPost, url, &authplane.DPoPProofOptions{AccessToken: accessToken}))
	// authplane:end

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", proof)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("HTTP %d\n%s", resp.StatusCode, out)
	}
	return string(out), nil
}

// must panics on a non-nil error; used here to keep the example's auth-setup
// block focused on the SDK calls themselves rather than canonical Go error
// handling. A production agent would log and exit cleanly instead.
func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}
