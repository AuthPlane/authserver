// Retrofit example — AFTER (Authplane added).
//
// This is the SAME server as ../before/main.go — same three tools, same
// modelcontextprotocol/go-sdk boilerplate, same net/http.ListenAndServe.
// The only changes are:
//
//   (a) the `// authplane:begin` / `// authplane:end` block (5 lines),
//   (b) `http.Handle(adapter.WellKnownPRMPath(), ...)` for the PRM doc,
//   (c) wrapping the MCP handler in `adapter.AuthMiddleware(...)`.
//
// Compare side-by-side:
//
//	diff -u ../before/main.go main.go
//
// That diff is the cost of adding auth to an existing go-sdk MCP server.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/authplane/go-sdk/mcp/pkg/authplanemcp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	ctx := context.Background()

	// === transport / MCP boilerplate ===========================================
	server := mcp.NewServer(&mcp.Implementation{Name: "retrofit-demo", Version: "1.0.0"}, nil)
	handler := mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return server }, nil,
	)

	// === Authplane integration =================================================
	// Five lines. `NewAdapter` does AS metadata discovery + JWKS fetch — the
	// AS must be reachable here or `must(...)` will log.Fatal.
	// `DevMode: true` relaxes the SDK's SSRF guard for local-dev only.
	// authplane:begin
	adapter := must(authplanemcp.NewAdapter(ctx, authplanemcp.Options{
		Issuer: os.Getenv("AUTHPLANE_ISSUER"), Resource: os.Getenv("AUTHPLANE_RESOURCE"),
		Scopes: []string{"mcp:tools"}, DevMode: true,
	}))
	defer adapter.Close()
	// authplane:end

	http.Handle(adapter.WellKnownPRMPath(), adapter.ProtectedResourceMetadataHandler())
	http.Handle("/mcp", adapter.AuthMiddleware(handler))

	// === your tools ============================================================
	mcp.AddTool(server, &mcp.Tool{
		Name:        "add",
		Description: "Add two numbers.",
	}, addTool)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "now_utc",
		Description: "Return the current time, in UTC, as RFC 3339.",
	}, nowTool)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "roll_dice",
		Description: "Roll `count` dice with `sides` faces each.",
	}, rollDiceTool)

	// When you change PORT, also update AUTHPLANE_RESOURCE so the JWT
	// `aud` claim still matches the URL the server actually serves on.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("MCP server (auth-enforced) listening on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

type addArgs struct {
	A float64 `json:"a"`
	B float64 `json:"b"`
}

func addTool(_ context.Context, _ *mcp.CallToolRequest, args addArgs) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%v", args.A+args.B)}},
	}, nil, nil
}

func nowTool(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: time.Now().UTC().Format(time.RFC3339)}},
	}, nil, nil
}

type rollDiceArgs struct {
	Sides int `json:"sides"`
	Count int `json:"count"`
}

func rollDiceTool(_ context.Context, _ *mcp.CallToolRequest, args rollDiceArgs) (*mcp.CallToolResult, any, error) {
	if args.Sides == 0 {
		args.Sides = 6
	}
	if args.Count == 0 {
		args.Count = 1
	}
	rolls := make([]int, 0, args.Count)
	sum := 0
	for i := 0; i < args.Count; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(args.Sides)))
		if err != nil {
			return nil, nil, err
		}
		v := int(n.Int64()) + 1
		rolls = append(rolls, v)
		sum += v
	}
	body, _ := json.Marshal(map[string]any{"rolls": rolls, "total": sum, "sides": args.Sides})
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(body)}},
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
