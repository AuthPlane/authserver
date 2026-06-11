// Retrofit example — BEFORE (unauthed).
//
// A perfectly ordinary modelcontextprotocol/go-sdk MCP server. Three small
// tools, streamable-http transport on port 8080, no auth at all. This is
// what 90% of MCP servers in the wild look like today.
//
// ../after/main.go shows the same server with Authplane wired in. The
// diff between this file and that one is the cost of adding auth.
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

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	// === transport / MCP boilerplate ===========================================
	server := mcp.NewServer(&mcp.Implementation{Name: "retrofit-demo", Version: "1.0.0"}, nil)
	handler := mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return server }, nil,
	)
	http.Handle("/mcp", handler)

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

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("MCP server (unauthed) listening on :%s", port)
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
