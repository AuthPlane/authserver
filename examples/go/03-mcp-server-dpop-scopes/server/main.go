// Tier 03 — MCP server with DPoP-bound tokens and per-tool scope enforcement (Go).
//
// Builds on tier 01:
//   - The AS issues DPoP-bound (RFC 9449) access tokens whose `cnf.jkt` claim
//     binds the token to the agent's DPoP key. The MCP adapter's
//     `AuthMiddleware` validates the JWT signature, audience, and expiry — the
//     `cnf.jkt` claim travels with the token and is visible to the handler
//     via `ClaimsFromContext` for any handler that wants to enforce it
//     explicitly.
//   - Two scoped tools (`echo` → `mcp:echo`, `add_numbers` → `mcp:add`) call
//     `claims.RequireScope(...)` so a token that lacks a scope cannot invoke
//     the corresponding tool. The middleware layer remains permissive — MCP
//     `initialize` and protocol messages must succeed with any valid token —
//     and the per-tool guard is the actual enforcement point.
//
// Auth-specific code lives between `// authplane:begin` / `// authplane:end`
// so the `tools/loccount` tool can audit the LOC budget for this tier.
//
// Run via the example's Makefile:
//
//	cp .env.example .env
//	make run
//	make verify
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/mcp/pkg/authplanemcp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	ctx := context.Background()

	// === transport / MCP boilerplate ===========================================
	server := mcp.NewServer(&mcp.Implementation{Name: "demo-server-tier03", Version: "1.0.0"}, nil)
	handler := mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return server }, nil,
	)

	// === Authplane integration =================================================
	// authplane:begin
	adapter := must(authplanemcp.NewAdapter(ctx, authplanemcp.Options{
		Issuer: os.Getenv("AUTHPLANE_ISSUER"), Resource: os.Getenv("AUTHPLANE_RESOURCE"),
		Scopes: []string{"mcp:echo", "mcp:add"}, DevMode: true,
	}))
	defer adapter.Close()
	// authplane:end

	http.Handle(adapter.WellKnownPRMPath(), adapter.ProtectedResourceMetadataHandler())
	http.Handle("/mcp", adapter.AuthMiddleware(handler))

	// === your tools ============================================================
	// Each tool calls RequireScope on the verified claims; the call sits inside
	// the authplane markers so the loccount tool charges it against the tier.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "echo",
		Description: "Echo the supplied text back to the caller. Requires scope mcp:echo.",
	}, echo)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "add_numbers",
		Description: "Return the sum of two numbers. Requires scope mcp:add.",
	}, addNumbers)

	log.Println("listening on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

type echoArgs struct {
	Text string `json:"text"`
}

func echo(ctx context.Context, _ *mcp.CallToolRequest, args echoArgs) (*mcp.CallToolResult, any, error) {
	// authplane:begin
	if err := requireScope(ctx, "mcp:echo"); err != nil { return nil, nil, err }
	// authplane:end
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: args.Text}},
	}, nil, nil
}

type addArgs struct {
	A float64 `json:"a"`
	B float64 `json:"b"`
}

func addNumbers(ctx context.Context, _ *mcp.CallToolRequest, args addArgs) (*mcp.CallToolResult, any, error) {
	// authplane:begin
	if err := requireScope(ctx, "mcp:add"); err != nil { return nil, nil, err }
	// authplane:end
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%g", args.A+args.B)}},
	}, nil, nil
}

// requireScope is a thin wrapper over ClaimsFromContext + RequireScope that
// keeps each tool handler's auth-marker block down to a single guard line.
// The body of this helper does not live inside markers — it is one-time
// scaffolding, not per-tool auth code.
func requireScope(ctx context.Context, scope string) error {
	claims := authplanemcp.ClaimsFromContext(ctx)
	if claims == nil {
		return verifier.ErrTokenMissing
	}
	return claims.RequireScope(scope)
}

// must panics on a non-nil error; used here to keep the example's auth-setup
// block focused on the SDK call itself rather than canonical Go error
// handling. A production server would log and exit cleanly instead.
func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}
