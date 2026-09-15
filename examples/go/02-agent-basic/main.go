// Tier 02 — Basic agent (Go).
//
// Minimal client that acquires an Authplane-issued access token via the
// `client_credentials` grant and calls the tier-01 MCP server's `echo` tool
// over JSON-RPC. The auth-specific code is wrapped between
// `// authplane:begin` / `// authplane:end` so the `tools/loccount` tool can
// audit the LOC budget for this tier.
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
)

func main() {
	ctx := context.Background()

	// === transport / HTTP client boilerplate =====================================
	mcpURL := os.Getenv("MCP_URL")
	resource := os.Getenv("AUTHPLANE_RESOURCE")

	// === Authplane integration =================================================
	// authplane:begin
	client := must(authplane.NewClient(ctx, os.Getenv("AUTHPLANE_ISSUER"),
		authplane.WithClientCredentials(os.Getenv("AUTHPLANE_CLIENT_ID"), os.Getenv("AUTHPLANE_CLIENT_SECRET")),
	))
	defer client.Close()
	tok := must(client.ClientCredentials(ctx, []string{"mcp:echo"}, []string{resource}))
	// authplane:end

	// === call the MCP tool =======================================================
	// Streamable HTTP needs the 3-step handshake before a tool call is legal:
	// `initialize` (the response carries `Mcp-Session-Id`), the one-way
	// `notifications/initialized`, then `tools/call` — every request after the
	// first carrying the session id. See docs/reference/mcp-streamable-http.md.
	post := func(session, body string) (string, []byte) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, mcpURL, bytes.NewReader([]byte(body)))
		if err != nil {
			log.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if session != "" {
			req.Header.Set("Mcp-Session-Id", session)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		if resp.StatusCode/100 != 2 {
			log.Fatalf("mcp call failed: HTTP %d\n%s", resp.StatusCode, out)
		}
		return resp.Header.Get("Mcp-Session-Id"), out
	}
	session, _ := post("", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"tier-02-agent","version":"1.0"}}}`)
	post(session, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	_, out := post(session, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello from tier-02 agent"}}}`)
	fmt.Printf("%s\n", out)
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
