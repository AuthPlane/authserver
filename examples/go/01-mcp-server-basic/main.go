// Tier 01 — Basic MCP server (Go).
//
// Minimal MCP server protected by Authplane-issued JWTs. The auth-specific
// code is wrapped between `// authplane:begin` / `// authplane:end` so the
// `tools/loccount` tool can audit the LOC budget for this tier.
//
// Run via the example's Makefile:
//
//	cp .env.example .env
//	make run
//	make verify
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/authplane/go-sdk/mcp/pkg/authplanemcp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	ctx := context.Background()

	// === transport / MCP boilerplate ===========================================
	server := mcp.NewServer(&mcp.Implementation{Name: "demo-server", Version: "1.0.0"}, nil)
	handler := mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return server }, nil,
	)

	// === Authplane integration =================================================
	// `NewAdapter` does AS metadata discovery + JWKS fetch. The AS MUST
	// be reachable here or `must(...)` will log.Fatal and the process
	// will exit before reaching net/http.ListenAndServe. The example's
	// docker-compose uses `depends_on:` + a healthcheck so this race
	// never fires (see docker-compose.yml). If you run outside compose,
	// either bring the AS up first or wrap the call:
	//
	//     var adapter *authplanemcp.Adapter
	//     for i := 0; i < 30; i++ {
	//         a, err := authplanemcp.NewAdapter(ctx, opts)
	//         if err == nil { adapter = a; break }
	//         time.Sleep(time.Second)
	//     }
	//     if adapter == nil { log.Fatal("authserver unreachable after 30s") }
	//
	// `DevMode: true` relaxes the SDK's SSRF guard so it will fetch from
	// http:// issuers, localhost, and private networks. It is for local
	// development only — production issuers MUST be https:// and DevMode
	// MUST be false (the default).
	// authplane:begin
	adapter := must(authplanemcp.NewAdapter(ctx, authplanemcp.Options{
		Issuer: os.Getenv("AUTHPLANE_ISSUER"), Resource: os.Getenv("AUTHPLANE_RESOURCE"),
		Scopes: []string{"mcp:echo"}, DevMode: true,
	}))
	defer adapter.Close()
	// authplane:end

	http.Handle(adapter.WellKnownPRMPath(), adapter.ProtectedResourceMetadataHandler())
	http.Handle("/mcp", adapter.AuthMiddleware(handler))

	// === your tools ============================================================
	mcp.AddTool(server, &mcp.Tool{
		Name:        "echo",
		Description: "Echo the supplied text back to the caller.",
	}, echo)

	// Port is read from PORT for one-touch retargeting. When you change it,
	// also update AUTHPLANE_RESOURCE so the JWT `aud` claim still matches.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("listening on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

type echoArgs struct {
	Text string `json:"text"`
}

func echo(_ context.Context, _ *mcp.CallToolRequest, args echoArgs) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: args.Text}},
	}, nil, nil
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
