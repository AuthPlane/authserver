package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseCobraTree_Fixture exercises the AST parser against a minimal
// in-memory cobra package. It asserts that:
//   - var declarations like `var fooCmd = &cobra.Command{...}` become
//     cobraCmd entries with Use/Short/Long/Example populated;
//   - rootCmd.AddCommand → tree edges build a path "authserver foo bar";
//   - Flags().String / Bool / Int / StringArray attach with correct types
//     and default-value rendering;
//   - the "(required)" sentinel partitions required vs optional flags;
//   - the source-ref footer reports the var declaration's file:LINE.
func TestParseCobraTree_Fixture(t *testing.T) {
	dir := t.TempDir()

	fixture := `package fixture

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:   "authserver",
	Short: "root",
}

var fooCmd = &cobra.Command{
	Use:   "foo",
	Short: "Foo things",
	Long:  "Foo is the canonical example command for the docsgen test.",
}

var fooBarCmd = &cobra.Command{
	Use:   "bar",
	Short: "Bar a foo",
	Long:  "Bar applies the bar operation. Required input is --slug.",
	Example: "authserver foo bar --slug widget",
}

func init() {
	rootCmd.AddCommand(fooCmd)
	fooCmd.AddCommand(fooBarCmd)

	fooBarCmd.Flags().String("slug", "", "Widget slug (required)")
	fooBarCmd.Flags().String("region", "us-east-1", "AWS region")
	fooBarCmd.Flags().Bool("dry-run", false, "Validate without persisting")
	fooBarCmd.Flags().Int("limit", 100, "Max rows")
	fooBarCmd.Flags().StringArray("scopes", nil, "Repeatable scope tuple 'name|upstream'")
}
`
	if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(fixture), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	tree, err := parseCobraTree(dir)
	if err != nil {
		t.Fatalf("parseCobraTree: %v", err)
	}
	if tree.Root.Use != "authserver" {
		t.Fatalf("root.Use = %q, want authserver", tree.Root.Use)
	}
	if len(tree.Root.Children) != 1 || tree.Root.Children[0].Use != "foo" {
		t.Fatalf("expected single child 'foo', got %+v", tree.Root.Children)
	}
	foo := tree.Root.Children[0]
	if len(foo.Children) != 1 || foo.Children[0].Use != "bar" {
		t.Fatalf("expected child 'bar', got %+v", foo.Children)
	}
	bar := foo.Children[0]
	if got := commandFullPath(bar); got != "authserver foo bar" {
		t.Fatalf("full path = %q, want authserver foo bar", got)
	}
	if got := cliAnchor(bar); got != "cli-foo-bar" {
		t.Fatalf("anchor = %q, want cli-foo-bar", got)
	}

	// Flag partition.
	req, opt := partitionFlags(bar.Flags)
	if len(req) != 1 || req[0].Name != "slug" {
		t.Fatalf("required flags = %+v, want [slug]", req)
	}
	if len(opt) != 4 {
		t.Fatalf("optional flags count = %d, want 4 (%+v)", len(opt), opt)
	}
	wantTypes := map[string]string{
		"region":  "string",
		"dry-run": "bool",
		"limit":   "int",
		"scopes":  "stringArray",
	}
	for _, f := range opt {
		if wantTypes[f.Name] != f.Type {
			t.Errorf("flag %q type = %q, want %q", f.Name, f.Type, wantTypes[f.Name])
		}
	}

	// Render and spot-check shape.
	body := renderCLIDoc(tree, cliQuirks{Commands: map[string]cliQuirksCmd{}}, dir)
	if !strings.HasPrefix(body, GeneratedByHeader) {
		t.Errorf("body does not start with GeneratedByHeader: %.80q", body)
	}
	wantContains := []string{
		"# CLI Reference",
		"## Index",
		"## `authserver foo bar`",
		`<a id="cli-foo-bar"></a>`,
		"**Synopsis** — `authserver foo bar --slug <slug> [flags]`",
		"### Required flags",
		"| `--slug` | `string` | Widget slug |",
		"### Optional flags",
		"| `--dry-run` | `bool` | `false` |",
		"| `--limit` | `int` | 100 |",
		"### Examples",
		"authserver foo bar --slug widget",
		"**Source** — `fixture.go:",
	}
	for _, w := range wantContains {
		if !strings.Contains(body, w) {
			t.Errorf("body missing %q", w)
		}
	}
}

// TestRunCLIGen_Idempotent asserts that two consecutive runs against the
// real cobra tree produce byte-identical output. This is the contract
// docs-check relies on (a generator that flaps between runs would
// produce diff noise on every PR).
func TestRunCLIGen_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path1, err := runCLIGen(dir)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	first, err := os.ReadFile(path1)
	if err != nil {
		t.Fatalf("read first: %v", err)
	}
	if !strings.HasPrefix(string(first), GeneratedByHeader) {
		t.Fatalf("first run does not start with GeneratedByHeader")
	}

	path2, err := runCLIGen(dir)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	second, err := os.ReadFile(path2)
	if err != nil {
		t.Fatalf("read second: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("output not idempotent: first/second differ in length %d vs %d", len(first), len(second))
	}
}

// TestQuirksLookup_Falls_Back exercises the override layer: when no
// quirk is registered for (cmdPath, flag), the lookup returns "" and
// rendering falls back to the cobra usage string. When a quirk *is*
// registered it preempts the usage string.
func TestQuirksLookup_FallsBack(t *testing.T) {
	q := cliQuirks{Commands: map[string]cliQuirksCmd{
		"admin resource create": {Flags: map[string]cliQuirksFlag{
			"--scopes": {Notes: "format: a|b|c"},
		}},
	}}
	if got := q.lookupFlagNotes("admin resource create", "scopes"); got != "format: a|b|c" {
		t.Errorf("known quirk = %q, want format: a|b|c", got)
	}
	if got := q.lookupFlagNotes("admin resource create", "slug"); got != "" {
		t.Errorf("unknown flag should return empty string, got %q", got)
	}
	if got := q.lookupFlagNotes("nonexistent", "scopes"); got != "" {
		t.Errorf("unknown cmd should return empty string, got %q", got)
	}
}

// TestStringLiteralValue_Concatenation guards the `"a" + "b" + "c"` shape
// used heavily in cmd/authserver/admin_resource.go's Long field.
func TestStringLiteralValue_Concatenation(t *testing.T) {
	fset := token.NewFileSet()
	src := `package x
var s = "hello, " + "world" + "!"
`
	file, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var expr ast.Expr
	ast.Inspect(file, func(n ast.Node) bool {
		if v, ok := n.(*ast.ValueSpec); ok && len(v.Values) > 0 {
			expr = v.Values[0]
			return false
		}
		return true
	})
	if expr == nil {
		t.Fatal("no value expr found")
	}
	if got := stringLiteralValue(expr); got != "hello, world!" {
		t.Errorf("got %q, want %q", got, "hello, world!")
	}
}
