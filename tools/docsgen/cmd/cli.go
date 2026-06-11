package cmd

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v3"

	"github.com/authplane/authserver/tools/docsgen/internal/mdwriter"
	"github.com/authplane/authserver/tools/docsgen/internal/srcref"
)

// cliCmdSourceDir is the package directory walked by the CLI generator.
// Relative to the repo root; the generator resolves it via repoRoot()
// so `go run ./tools/docsgen cli` works from any cwd.
const cliCmdSourceDir = "cmd/authserver"

// cliQuirksPath is the override file documented in
// tools/docsgen/quirks/README.md. Absent file = no overrides (warn-only).
const cliQuirksPath = "tools/docsgen/quirks/cli.yaml"

// newCLICmd returns the `docsgen cli` subcommand. It walks the cobra
// command tree declared in cmd/authserver/ via static AST analysis (the
// package is `main` and thus cannot be imported) and emits a single
// docs/reference/cli.md.
func newCLICmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "cli",
		Short: "Generate the CLI reference (docs/reference/cli.md)",
		RunE: func(cmd *cobra.Command, args []string) error {
			outDir, err := cmd.Flags().GetString("out")
			if err != nil {
				return err
			}
			target, err := runCLIGen(outDir)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", target)
			return nil
		},
	}
	return c
}

// runCLIGen is the testable entry point: parse, render, write. Returns
// the path of the file written.
func runCLIGen(outDir string) (string, error) {
	root, err := repoRoot()
	if err != nil {
		return "", fmt.Errorf("locate repo root: %w", err)
	}
	srcDir := filepath.Join(root, cliCmdSourceDir)

	tree, err := parseCobraTree(srcDir)
	if err != nil {
		return "", fmt.Errorf("parse cobra tree: %w", err)
	}

	quirks, _ := loadCLIQuirks(filepath.Join(root, cliQuirksPath))

	body := renderCLIDoc(tree, quirks, root)

	if err := os.MkdirAll(outDir, 0o755); err != nil { //nolint:gosec // G301: docs/ dir is world-readable by design
		return "", fmt.Errorf("create out dir: %w", err)
	}
	target := filepath.Join(outDir, "cli.md")
	if err := os.WriteFile(target, []byte(body), 0o644); err != nil { //nolint:gosec // G306: generated docs are world-readable by design
		return "", fmt.Errorf("write %s: %w", target, err)
	}
	return target, nil
}

// repoRoot walks up from the working directory looking for go.mod; the
// generator works regardless of where it is invoked from (CI runs it
// from the repo root; developers may invoke it from anywhere).
func repoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod above %s", cwd)
		}
		dir = parent
	}
}

// -----------------------------------------------------------------------
// Cobra tree model
// -----------------------------------------------------------------------

// cobraCmd is the in-memory representation of one parsed `var fooCmd =
// &cobra.Command{...}` declaration plus the flags attached to it via
// `init()` blocks.
type cobraCmd struct {
	// VarName is the package-level var name (e.g. `resourceCreateCmd`).
	VarName string
	// Use is the cobra `Use:` field (the single token, e.g. "create").
	Use string
	// Short / Long / Example mirror the cobra fields.
	Short   string
	Long    string
	Example string
	// Pos is the start position of the var declaration; used by srcref
	// to render the "file:LINE" footer for each section.
	Pos token.Pos

	// Children is filled during tree assembly from AddCommand edges.
	Children []*cobraCmd
	// Parent is set during tree assembly; nil for the synthetic root.
	Parent *cobraCmd
	// Flags is the ordered (insertion-order) flag list parsed from the
	// init() block(s) that bind flags to this command.
	Flags []*cobraFlag
}

// cobraFlag is one `.Flags().<Type>(name, default, usage)` call.
type cobraFlag struct {
	Name    string
	Type    string
	Default string
	Usage   string
}

// cobraTree holds the parsed package as a forest rooted at "authserver".
type cobraTree struct {
	// Root is the synthetic root command (Use="authserver"). Its
	// Children are the top-level commands attached to rootCmd in main.go.
	Root *cobraCmd
	// FSet is the token.FileSet shared by every Pos for source-ref rendering.
	FSet *token.FileSet
}

// parseCobraTree walks every non-test .go file in srcDir, builds a map
// from cobra-var name to cobraCmd, attaches flags from init() blocks,
// and resolves AddCommand edges into a single tree rooted at rootCmd.
func parseCobraTree(srcDir string) (*cobraTree, error) {
	fset := token.NewFileSet()
	// Manually walk the directory: parser.ParseDir was deprecated in Go 1.25
	// and we only need the flat list of non-test .go files from the
	// cmd/authserver/ package (single-package directory).
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return nil, err
	}
	files := make([]*ast.File, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		full := filepath.Join(srcDir, e.Name())
		file, err := parser.ParseFile(fset, full, nil, parser.ParseComments) //nolint:gosec // G304: walking cmd/authserver/ Go sources
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}

	cmds := map[string]*cobraCmd{}
	// Use a slice to preserve discovery order for deterministic output
	// when two cobra paths sort the same (defensive — sort by path is
	// the canonical ordering, but discovery order is a stable tiebreak).
	for _, file := range files {
		collectCobraCommands(file, cmds)
	}
	// Second pass: bind flags + AddCommand edges from init() blocks
	// after every command var is known so forward references work.
	rootChildren := []*cobraCmd{}
	for _, file := range files {
		bindInitBlock(file, cmds, &rootChildren)
	}

	// Synthesize the rootCmd as the parent. Its Use is the binary name.
	root := &cobraCmd{
		VarName: "rootCmd",
		Use:     "authserver",
		Short:   "Authplane MCP Authorization Server",
		Long:    "A self-hosted OAuth 2.1 Authorization Server purpose-built for MCP.",
	}
	for _, c := range rootChildren {
		c.Parent = root
		root.Children = append(root.Children, c)
	}
	// Sort each level for deterministic traversal.
	sortCobraTree(root)
	return &cobraTree{Root: root, FSet: fset}, nil
}

// collectCobraCommands populates cmds with one entry per
// `var xCmd = &cobra.Command{...}` declaration found in file.
func collectCobraCommands(file *ast.File, cmds map[string]*cobraCmd) {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				cc := parseCobraCommandLit(vs.Values[i])
				if cc == nil {
					continue
				}
				cc.VarName = name.Name
				cc.Pos = vs.Pos()
				cmds[name.Name] = cc
			}
		}
	}
}

// parseCobraCommandLit returns a *cobraCmd if expr is `&cobra.Command{...}`,
// otherwise nil. Extracts Use/Short/Long/Example from the literal's
// elements; non-string fields and any RunE/Args bodies are ignored.
func parseCobraCommandLit(expr ast.Expr) *cobraCmd {
	unary, ok := expr.(*ast.UnaryExpr)
	if !ok || unary.Op != token.AND {
		return nil
	}
	lit, ok := unary.X.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "cobra" || sel.Sel.Name != "Command" {
		return nil
	}
	cc := &cobraCmd{}
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		val := stringLiteralValue(kv.Value)
		if val == "" && kv.Value != nil {
			// Non-string field (Args, RunE, Run, SilenceUsage, etc.) — skip.
			continue
		}
		switch key.Name {
		case "Use":
			cc.Use = val
		case "Short":
			cc.Short = val
		case "Long":
			cc.Long = val
		case "Example":
			cc.Example = val
		}
	}
	return cc
}

// stringLiteralValue collapses one of:
//   - a bare basic-lit string ("foo")
//   - a BinaryExpr concatenation of basic-lit strings ("a" + "b" + ...)
//
// into the concatenated Go-decoded value. Returns "" for anything else
// (function calls, identifiers, etc.) so the caller can detect a
// non-string field.
func stringLiteralValue(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return ""
		}
		s, err := strconv.Unquote(e.Value)
		if err != nil {
			return ""
		}
		return s
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return ""
		}
		l := stringLiteralValue(e.X)
		r := stringLiteralValue(e.Y)
		if l == "" && r == "" {
			return ""
		}
		return l + r
	}
	return ""
}

// bindInitBlock walks every top-level `func init() { ... }` in file and
// records the side effects we care about:
//   - `parent.AddCommand(child)` → tree edges
//   - `cmd.Flags().<Type>(name, default, usage)` → flag entries
//   - `rootCmd.AddCommand(child)` → recorded into rootChildren
func bindInitBlock(file *ast.File, cmds map[string]*cobraCmd, rootChildren *[]*cobraCmd) {
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "init" || fd.Recv != nil || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			processInitCall(call, cmds, rootChildren)
			return true
		})
	}
}

// processInitCall dispatches one call expression in an init() body.
// It only recognizes AddCommand edges and the small set of flag-binding
// shapes used in cmd/authserver/.
func processInitCall(call *ast.CallExpr, cmds map[string]*cobraCmd, rootChildren *[]*cobraCmd) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}

	// `parent.AddCommand(child)` — parent and child are both idents.
	if sel.Sel.Name == "AddCommand" {
		parentIdent, ok2 := sel.X.(*ast.Ident)
		if !ok2 || len(call.Args) == 0 {
			return
		}
		for _, arg := range call.Args {
			childIdent, ok3 := arg.(*ast.Ident)
			if !ok3 {
				continue
			}
			child, ok4 := cmds[childIdent.Name]
			if !ok4 {
				continue
			}
			if parentIdent.Name == "rootCmd" {
				*rootChildren = append(*rootChildren, child)
				continue
			}
			parent, ok5 := cmds[parentIdent.Name]
			if !ok5 {
				continue
			}
			child.Parent = parent
			parent.Children = append(parent.Children, child)
		}
		return
	}

	// Flag binding: `cmdVar.Flags().<Type>(...)` or `.PersistentFlags().<Type>(...)`.
	// The selector is the flag-type method; sel.X is the .Flags() call.
	flagMethod := sel.Sel.Name
	flagsCall, ok := sel.X.(*ast.CallExpr)
	if !ok {
		return
	}
	flagsSel, ok := flagsCall.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	if flagsSel.Sel.Name != "Flags" && flagsSel.Sel.Name != "PersistentFlags" {
		return
	}
	cmdIdent, ok := flagsSel.X.(*ast.Ident)
	if !ok {
		return
	}
	cc, ok := cmds[cmdIdent.Name]
	if !ok {
		return
	}
	flag := parseFlagCall(flagMethod, call.Args)
	if flag == nil {
		return
	}
	cc.Flags = append(cc.Flags, flag)
}

// parseFlagCall extracts (name, default, usage) from a cobra flag call.
// Supported method shapes (matching everything used in cmd/authserver/):
//
//	Flags().String(name, default, usage)
//	Flags().Bool(name, default, usage)
//	Flags().Int(name, default, usage)
//	Flags().StringArray(name, default, usage)
//	Flags().StringSlice(name, default, usage)
//	Flags().Duration(name, default, usage)
//	Flags().StringVar(&v, name, default, usage)
//	Flags().DurationVar(&v, name, default, usage)
//	...
//
// The *Var forms shift the name/default/usage args one slot right.
// Unsupported shapes return nil (silently skipped).
func parseFlagCall(method string, args []ast.Expr) *cobraFlag {
	// Map method → user-facing type token + arg layout.
	typeName, isVar := flagMethodToType(method)
	if typeName == "" {
		return nil
	}

	offset := 0
	if isVar {
		offset = 1 // first arg is &varRef
	}
	if len(args) < offset+3 {
		return nil
	}
	name := stringLiteralValue(args[offset])
	if name == "" {
		return nil
	}
	def := exprToDefaultString(args[offset+1])
	usage := stringLiteralValue(args[offset+2])
	return &cobraFlag{Name: name, Type: typeName, Default: def, Usage: usage}
}

// flagMethodToType maps a pflag method name to (type token, isVar form).
// Returns ("", false) for unrecognized methods so the AST walker can
// skip them silently.
func flagMethodToType(method string) (string, bool) {
	// `*Var` and `*VarP` shift args; treat them uniformly.
	isVar := false
	base := method
	switch {
	case strings.HasSuffix(method, "VarP"):
		isVar = true
		base = strings.TrimSuffix(method, "VarP")
	case strings.HasSuffix(method, "Var"):
		isVar = true
		base = strings.TrimSuffix(method, "Var")
	case strings.HasSuffix(method, "P"):
		// e.g. StringP — same arg layout as String, just with a shorthand.
		// We collapse to the base type name; the shorthand letter (4th arg)
		// is ignored. None of cmd/authserver/ uses this today, so this is
		// a forward-looking pass-through.
		base = strings.TrimSuffix(method, "P")
	}
	switch base {
	case "String":
		return "string", isVar
	case "Bool":
		return "bool", isVar
	case "Int":
		return "int", isVar
	case "Int64":
		return "int64", isVar
	case "Float64":
		return "float64", isVar
	case "Duration":
		return "duration", isVar
	case "StringArray":
		return "stringArray", isVar
	case "StringSlice":
		return "stringSlice", isVar
	case "IntSlice":
		return "intSlice", isVar
	case "Count":
		return "count", isVar
	}
	return "", false
}

// exprToDefaultString renders the AST default-value expression as a
// human-friendly Markdown cell. It handles the literal shapes used in
// cmd/authserver/ and falls back to the empty string for anything fancy.
func exprToDefaultString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			if s, err := strconv.Unquote(e.Value); err == nil {
				if s == "" {
					return ""
				}
				return "`" + s + "`"
			}
			return e.Value
		}
		return e.Value
	case *ast.Ident:
		switch e.Name {
		case "true", "false":
			return "`" + e.Name + "`"
		case "nil":
			return ""
		default:
			// Named constant — surface the identifier; operators can grep
			// the source for its value if it's load-bearing.
			return "`" + e.Name + "`"
		}
	case *ast.SelectorExpr:
		// e.g. `time.Hour` / `defaultPurgeTimeout`. Render verbatim.
		if x, ok := e.X.(*ast.Ident); ok {
			return "`" + x.Name + "." + e.Sel.Name + "`"
		}
	}
	return ""
}

// sortCobraTree sorts every level of the tree by Use so output is
// alphabetical and deterministic regardless of file/declaration order.
func sortCobraTree(c *cobraCmd) {
	sort.SliceStable(c.Children, func(i, j int) bool {
		return c.Children[i].Use < c.Children[j].Use
	})
	for _, child := range c.Children {
		sortCobraTree(child)
	}
}

// -----------------------------------------------------------------------
// Quirks file
// -----------------------------------------------------------------------

// cliQuirks is the YAML-decoded shape of tools/docsgen/quirks/cli.yaml.
type cliQuirks struct {
	Commands map[string]cliQuirksCmd `yaml:"commands"`
}

type cliQuirksCmd struct {
	Flags map[string]cliQuirksFlag `yaml:"flags"`
}

type cliQuirksFlag struct {
	Notes string `yaml:"notes"`
}

// loadCLIQuirks reads and decodes the quirks YAML. An absent or empty
// file is not an error — the caller falls back to cobra usage strings.
func loadCLIQuirks(path string) (cliQuirks, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: reading the quirks YAML alongside the source
	if err != nil {
		return cliQuirks{Commands: map[string]cliQuirksCmd{}}, err
	}
	var out cliQuirks
	if err := yaml.Unmarshal(raw, &out); err != nil {
		return cliQuirks{Commands: map[string]cliQuirksCmd{}}, err
	}
	if out.Commands == nil {
		out.Commands = map[string]cliQuirksCmd{}
	}
	return out, nil
}

// lookupFlagNotes returns the override notes for (cmdPath, flagName) or
// "" if no entry exists. cmdPath is the cobra path WITHOUT the
// `authserver` prefix (e.g. `admin resource create`).
func (q cliQuirks) lookupFlagNotes(cmdPath, flagName string) string {
	c, ok := q.Commands[cmdPath]
	if !ok {
		return ""
	}
	f, ok := c.Flags["--"+flagName]
	if !ok {
		return ""
	}
	return strings.TrimSpace(f.Notes)
}

// -----------------------------------------------------------------------
// Rendering
// -----------------------------------------------------------------------

// renderCLIDoc returns the full cli.md document body.
func renderCLIDoc(tree *cobraTree, quirks cliQuirks, repoRootPath string) string {
	// Flatten the tree into a sorted-by-path list of leaf + non-leaf nodes
	// EXCLUDING the synthetic root (we describe top-level commands in the
	// per-command H2s).
	flat := flattenCobraTree(tree.Root)
	// Drop the root itself; render its descendants.
	if len(flat) > 0 && flat[0] == tree.Root {
		flat = flat[1:]
	}
	sort.SliceStable(flat, func(i, j int) bool {
		return commandFullPath(flat[i]) < commandFullPath(flat[j])
	})

	src := srcref.New(tree.FSet)

	var b strings.Builder
	b.WriteString(GeneratedByHeader)
	b.WriteString("\n\n")
	b.WriteString("# CLI Reference\n\n")
	b.WriteString(renderPreamble(tree.Root))
	b.WriteString("\n\n")

	// Index.
	b.WriteString("## Index\n\n")
	idx := &mdwriter.Table{Headers: []string{"Command", "Synopsis"}}
	for _, c := range flat {
		path := commandFullPath(c)
		anchor := cliAnchor(c)
		idx.Rows = append(idx.Rows, []string{
			"[`" + path + "`](#" + anchor + ")",
			singleLine(c.Short),
		})
	}
	b.WriteString(idx.Render())
	b.WriteString("\n")

	// Per-command sections.
	for _, c := range flat {
		b.WriteString(renderCommandSection(c, quirks, src, repoRootPath))
	}
	return b.String()
}

// renderPreamble returns the one-paragraph header that follows the H1.
// Built from the cobra rootCmd.Long, trimmed and reformatted so it sits
// well in Markdown.
func renderPreamble(root *cobraCmd) string {
	long := strings.TrimSpace(root.Long)
	if long == "" {
		long = strings.TrimSpace(root.Short)
	}
	return "The `authserver` binary exposes the operator surface for the " +
		"Authplane MCP Authorization Server. " + long + " " +
		"Top-level subcommands include `serve` (run the AS), `admin` " +
		"(client / user / key / resource / provider / grant / issuance / " +
		"fronting management), `migrate` (run DB migrations), `purge` " +
		"(one-shot expired-data cleanup), and `version` (print build " +
		"version). The sections below are auto-generated from the cobra " +
		"command tree in `cmd/authserver/`; flag tables include any " +
		"format-syntax notes from `tools/docsgen/quirks/cli.yaml`."
}

// flattenCobraTree returns nodes in pre-order traversal. Children at
// each level are already sorted by Use (see sortCobraTree).
func flattenCobraTree(c *cobraCmd) []*cobraCmd {
	out := []*cobraCmd{c} //nolint:prealloc // initial element is c; loop bound depends on tree traversal
	for _, child := range c.Children {
		out = append(out, flattenCobraTree(child)...)
	}
	return out
}

// commandFullPath returns the space-joined Use chain from rootCmd down
// to c, e.g. "authserver admin resource create".
func commandFullPath(c *cobraCmd) string {
	parts := []string{}
	for cur := c; cur != nil; cur = cur.Parent {
		parts = append([]string{cur.Use}, parts...)
	}
	return strings.Join(parts, " ")
}

// commandPathSansRoot returns the path WITHOUT the leading "authserver",
// matching the quirks-file key shape.
func commandPathSansRoot(c *cobraCmd) string {
	full := commandFullPath(c)
	const prefix = "authserver "
	if strings.HasPrefix(full, prefix) {
		return full[len(prefix):]
	}
	return full
}

// cliAnchor returns the stable HTML-comment anchor slug for c, e.g.
// `cli-admin-resource-create` (no `authserver` prefix).
func cliAnchor(c *cobraCmd) string {
	return "cli-" + mdwriter.Slug(commandPathSansRoot(c))
}

// renderCommandSection produces the H2 block for one cobra command:
// header, anchor, synopsis, required/optional flag tables, examples,
// and source-ref footer.
func renderCommandSection(c *cobraCmd, quirks cliQuirks, src *srcref.SrcRef, repoRootPath string) string {
	var b strings.Builder
	path := commandFullPath(c)
	b.WriteString("## `")
	b.WriteString(path)
	b.WriteString("`\n\n")
	b.WriteString(`<a id="`)
	b.WriteString(cliAnchor(c))
	b.WriteString("\"></a>\n\n")

	// Synopsis: command path + summary of required flags + `[flags]`.
	b.WriteString("**Synopsis** — `")
	b.WriteString(synopsis(c))
	b.WriteString("`\n\n")

	if s := strings.TrimSpace(c.Short); s != "" {
		b.WriteString("**Short** — ")
		b.WriteString(singleLine(s))
		b.WriteString("\n\n")
	}
	if l := strings.TrimSpace(c.Long); l != "" && l != strings.TrimSpace(c.Short) {
		b.WriteString("**Long**\n\n")
		// Quote-wrap the long description so internal newlines render
		// without leaking into the surrounding tables.
		for _, line := range strings.Split(l, "\n") {
			b.WriteString("> ")
			b.WriteString(line)
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	required, optional := partitionFlags(c.Flags)

	if len(required) > 0 {
		b.WriteString("### Required flags\n\n")
		b.WriteString(renderFlagTable(required, c, quirks, true))
		b.WriteString("\n")
	}
	if len(optional) > 0 {
		b.WriteString("### Optional flags\n\n")
		b.WriteString(renderFlagTable(optional, c, quirks, false))
		b.WriteString("\n")
	}

	if ex := strings.TrimSpace(c.Example); ex != "" {
		b.WriteString("### Examples\n\n")
		b.WriteString(mdwriter.CodeBlock("bash", ex))
		b.WriteString("\n")
	}

	if ref := src.Format(c.Pos, repoRootPath); ref != "" {
		b.WriteString("**Source** — `")
		b.WriteString(ref)
		b.WriteString("`\n\n")
	}
	return b.String()
}

// synopsis renders the one-line synopsis used as the **Synopsis** entry.
// Required flags appear as `--name <name>`; presence of any optional flags
// adds a trailing ` [flags]`.
func synopsis(c *cobraCmd) string {
	required, optional := partitionFlags(c.Flags)
	parts := []string{commandFullPath(c)}
	for _, f := range required {
		parts = append(parts, "--"+f.Name+" <"+f.Name+">")
	}
	if len(optional) > 0 {
		parts = append(parts, "[flags]")
	}
	return strings.Join(parts, " ")
}

// partitionFlags splits c.Flags into (required, optional) by the
// "(required)" sentinel embedded in the cobra usage string. This is the
// only required-ness signal cmd/authserver/ exposes — none of its
// commands call MarkFlagRequired today; required-ness is enforced
// in RunE bodies and surfaced to operators via the usage string. The
// generator inherits that signal verbatim. Both slices preserve
// insertion order so the rendered tables match how the operator reads
// the source.
func partitionFlags(flags []*cobraFlag) (required, optional []*cobraFlag) {
	for _, f := range flags {
		if isRequiredUsage(f.Usage) {
			required = append(required, f)
		} else {
			optional = append(optional, f)
		}
	}
	// Sort each bucket alphabetically by name for stable output.
	sort.SliceStable(required, func(i, j int) bool { return required[i].Name < required[j].Name })
	sort.SliceStable(optional, func(i, j int) bool { return optional[i].Name < optional[j].Name })
	return required, optional
}

// isRequiredUsage reports whether a cobra usage string declares the flag
// unconditionally required. The convention in cmd/authserver/ is a
// trailing "(required)" substring. Variants like
// "(required for broker resources)" describe a *conditional* requirement
// — those flags surface in the Optional table with the note intact,
// because the operator only supplies them in a subset of invocations.
func isRequiredUsage(usage string) bool {
	return strings.Contains(strings.ToLower(usage), "(required)")
}

// renderFlagTable returns a Markdown table for one bucket of flags.
// Required tables omit the Default column (every required value is
// supplied by the operator); optional tables include it.
func renderFlagTable(flags []*cobraFlag, c *cobraCmd, quirks cliQuirks, required bool) string {
	var t *mdwriter.Table
	if required {
		t = &mdwriter.Table{Headers: []string{"Flag", "Type", "Notes"}}
	} else {
		t = &mdwriter.Table{Headers: []string{"Flag", "Type", "Default", "Notes"}}
	}
	path := commandPathSansRoot(c)
	for _, f := range flags {
		notes := strings.TrimSpace(quirks.lookupFlagNotes(path, f.Name))
		if notes == "" {
			notes = cleanUsage(f.Usage)
		} else {
			notes = inlineMarkdown(notes)
		}
		if required {
			t.Rows = append(t.Rows, []string{"`--" + f.Name + "`", "`" + f.Type + "`", notes})
		} else {
			t.Rows = append(t.Rows, []string{"`--" + f.Name + "`", "`" + f.Type + "`", f.Default, notes})
		}
	}
	return t.Render()
}

// cleanUsage strips the literal "(required)" marker from a cobra usage
// string so the Required bucket doesn't restate the sentinel. Conditional
// forms like "(required for broker resources)" stay intact because they
// carry semantic content the operator needs.
func cleanUsage(u string) string {
	out := singleLine(u)
	out = strings.ReplaceAll(out, "(required)", "")
	return strings.TrimSpace(out)
}

// inlineMarkdown collapses multi-line Markdown into a single table cell.
// We replace blank lines with `<br><br>` and single newlines with `<br>`
// so basic line structure survives inside the table.
func inlineMarkdown(s string) string {
	// Normalize line endings, collapse trailing whitespace per line.
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = strings.TrimRight(ln, " \t")
	}
	// Drop trailing blank lines.
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	var out strings.Builder
	prevBlank := false
	for i, ln := range lines {
		if ln == "" {
			if !prevBlank {
				out.WriteString("<br><br>")
				prevBlank = true
			}
			continue
		}
		if i > 0 && !prevBlank {
			out.WriteString("<br>")
		}
		out.WriteString(ln)
		prevBlank = false
	}
	return out.String()
}

// singleLine flattens a multi-line string into a single line. Used in
// table cells where Markdown line-breaks would break the row layout.
func singleLine(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	// Collapse runs of whitespace.
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	return s
}
