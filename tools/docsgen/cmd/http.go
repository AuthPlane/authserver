package cmd

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/authplane/authserver/tools/docsgen/internal/mdwriter"
	"github.com/authplane/authserver/tools/docsgen/internal/srcref"
)

// httpRouteSrcDirs is the set of repo-relative directories the HTTP
// generator scans for route registrations (mux.Handle / mux.HandleFunc
// calls using the Go 1.22+ ServeMux "METHOD /path" pattern syntax). The
// project does not use chi; route registration is plain stdlib + the
// shared shared.SessionMiddleware wrapper.
var httpRouteSrcDirs = []string{
	"api/admin",
	"api/public",
	"api/public/oauth",
	"api/public/wellknown",
	"api/public/connection",
	"api/shared",
}

// httpDTOSrcFiles is the set of repo-relative .go files the HTTP
// generator scans for DTO struct definitions. These are the
// ground-truth wire-shape files per the project memory
// (`feedback_openapi_not_ground_truth`).
var httpDTOSrcFiles = []string{
	"api/admin/dto.go",
	"api/public/oauth/dto.go",
	"api/public/wellknown/dto.go",
	"api/shared/errors.go",
	"internal/admin/dto/dto.go",
}

// newHTTPCmd returns the `docsgen http` subcommand. The real generator
// walks the route-registration files and DTO struct definitions and
// produces a single docs/reference/http-api.md.
func newHTTPCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "http",
		Short: "Generate the HTTP API reference (docs/reference/http-api.md)",
		RunE: func(cmd *cobra.Command, args []string) error {
			outDir, err := cmd.Flags().GetString("out")
			if err != nil {
				return err
			}
			target, err := runHTTPGen(outDir)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", target)
			return nil
		},
	}
	return c
}

// runHTTPGen is the testable entry point: parse, render, write. Returns
// the path of the file written.
func runHTTPGen(outDir string) (string, error) {
	root, err := repoRoot()
	if err != nil {
		return "", fmt.Errorf("locate repo root: %w", err)
	}

	model, err := buildHTTPModel(root)
	if err != nil {
		return "", fmt.Errorf("parse http model: %w", err)
	}

	body := renderHTTPDoc(model, root)

	if err := os.MkdirAll(outDir, 0o755); err != nil { //nolint:gosec // G301: docs/ dir is world-readable by design
		return "", fmt.Errorf("create out dir: %w", err)
	}
	target := filepath.Join(outDir, "http-api.md")
	if err := os.WriteFile(target, []byte(body), 0o644); err != nil { //nolint:gosec // G306: generated docs are world-readable by design
		return "", fmt.Errorf("write %s: %w", target, err)
	}
	return target, nil
}

// -----------------------------------------------------------------------
// HTTP model
// -----------------------------------------------------------------------

// httpRoute is one parsed route registration.
type httpRoute struct {
	Method   string // GET, POST, ...
	Path     string // "/admin/clients"
	Server   string // "public" | "admin"
	AuthMode string // "admin-api-key", "session", "none"
	Pos      token.Pos
	// Handler is the name of the handler method the route is wired to
	// (e.g. "handleQueryAudit"), when the registration names one directly
	// or through a middleware wrapper; "" when it could not be resolved.
	Handler string
	// Receiver is the type of the value Handler is called on ("handlers",
	// "resourceAdminHandler"), resolved from the nearest preceding
	// `v := &T{...}` in the registering function; "" when unknown.
	Receiver string
	// Dir is the repo-relative directory the registration lives in; the
	// handler body is looked up in the same package.
	Dir string
	// Query lists the URL query parameters the handler reads
	// (r.URL.Query().Get("x"), q.Get("x"), q.Has("x")), sorted.
	Query []string
}

// httpDTO is one parsed struct type with json-tagged fields.
type httpDTO struct {
	Name    string
	Pos     token.Pos
	Fields  []httpDTOField
	Comment string
	// FilePath is the repo-relative path of the source file (used by
	// srcref when the struct's token.Pos lives in a FileSet we no longer
	// have a handle to).
	FilePath string
}

// httpDTOField is one struct field with its rendered JSON shape.
type httpDTOField struct {
	JSONName  string
	Type      string // human-readable type (e.g. "string", "[]ScopeView", "*time.Time")
	Required  bool   // !pointer && !omitempty (heuristic)
	OmitEmpty bool
	Notes     string // inline doc comment if present
	// RefDTO is the bare DTO type name if Type references another
	// captured DTO (used to link from the field row to the DTO section).
	RefDTO string
}

// httpModel is the full parsed representation.
type httpModel struct {
	Routes []httpRoute
	DTOs   []httpDTO
	FSet   *token.FileSet
}

// buildHTTPModel scans the route + DTO files under root and returns
// the in-memory representation rendered by renderHTTPDoc.
func buildHTTPModel(root string) (*httpModel, error) {
	fset := token.NewFileSet()
	m := &httpModel{FSet: fset}
	funcs := map[string]*ast.FuncDecl{}

	for _, rel := range httpRouteSrcDirs {
		dir := filepath.Join(root, rel)
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			full := filepath.Join(dir, e.Name())
			file, err := parser.ParseFile(fset, full, nil, parser.ParseComments)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", full, err)
			}
			collectRoutes(file, rel, &m.Routes)
			collectFuncs(file, rel, funcs)
		}
	}

	// Attach the query parameters each handler reads. The handler lives in
	// the same package as its registration; when the receiver type could
	// not be resolved, fall back to the name only if it is unambiguous in
	// that package.
	for i := range m.Routes {
		r := &m.Routes[i]
		if r.Handler == "" {
			continue
		}
		fd, ok := funcs[funcKey(r.Dir, r.Receiver, r.Handler)]
		if !ok {
			var matches []*ast.FuncDecl
			for k, f := range funcs {
				if strings.HasPrefix(k, r.Dir+"\x00") && strings.HasSuffix(k, "\x00"+r.Handler) {
					matches = append(matches, f)
				}
			}
			if len(matches) != 1 {
				fmt.Fprintf(os.Stderr, "docsgen http: %s %s: handler %s has %d candidates in %s and no resolved receiver; query parameters omitted\n", r.Method, r.Path, r.Handler, len(matches), r.Dir)
				continue
			}
			fd = matches[0]
		}
		r.Query = queryParams(fd)
	}

	for _, rel := range httpDTOSrcFiles {
		full := filepath.Join(root, rel)
		if _, err := os.Stat(full); err != nil {
			continue
		}
		file, err := parser.ParseFile(fset, full, nil, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", full, err)
		}
		collectDTOs(file, rel, &m.DTOs)
	}

	// Deduplicate by (method, path). Some files register a path twice
	// (e.g. api/public/connection/routes.go binds both the real
	// handler and a feature-disabled stub depending on Deps.Connect
	// being nil). Keep the first occurrence so the source ref points at
	// the canonical wiring site.
	{
		seen := map[string]bool{}
		out := m.Routes[:0]
		for _, r := range m.Routes {
			key := r.Method + " " + r.Path
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, r)
		}
		m.Routes = out
	}

	// Stable sort: routes by (path, method); DTOs by name.
	sort.SliceStable(m.Routes, func(i, j int) bool {
		if m.Routes[i].Path != m.Routes[j].Path {
			return m.Routes[i].Path < m.Routes[j].Path
		}
		return m.Routes[i].Method < m.Routes[j].Method
	})
	sort.SliceStable(m.DTOs, func(i, j int) bool {
		return m.DTOs[i].Name < m.DTOs[j].Name
	})

	// Cross-link DTO field types to other captured DTOs.
	known := map[string]bool{}
	for _, d := range m.DTOs {
		known[d.Name] = true
	}
	for di := range m.DTOs {
		for fi := range m.DTOs[di].Fields {
			f := &m.DTOs[di].Fields[fi]
			bare := bareTypeName(f.Type)
			if bare != "" && known[bare] {
				f.RefDTO = bare
			}
		}
	}

	return m, nil
}

// collectRoutes walks file looking for mux.Handle("METHOD /path", ...)
// and mux.HandleFunc("METHOD /path", ...) calls and appends one
// httpRoute per match.
func collectRoutes(file *ast.File, relDir string, out *[]httpRoute) {
	server := serverFromDir(relDir)
	for _, d := range file.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		collectRoutesIn(fd, file, relDir, server, out)
	}
}

// receiverBinding is one `v := &T{...}` (or `v := T{...}`) assignment in a
// registering function, used to resolve which type a `v.handleX` refers to.
type receiverBinding struct {
	Var  string
	Type string
	Pos  token.Pos
}

// collectRoutesIn walks one function body for route registrations.
func collectRoutesIn(fd *ast.FuncDecl, file *ast.File, relDir, server string, out *[]httpRoute) {
	var bindings []receiverBinding
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		id, ok := as.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		if t := compositeTypeName(as.Rhs[0]); t != "" {
			bindings = append(bindings, receiverBinding{Var: id.Name, Type: t, Pos: as.Pos()})
		}
		return true
	})
	resolve := func(v string, at token.Pos) string {
		best := ""
		var bestPos token.Pos
		for _, b := range bindings {
			if b.Var == v && b.Pos < at && b.Pos > bestPos {
				best, bestPos = b.Type, b.Pos
			}
		}
		return best
	}
	_ = file
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc" {
			return true
		}
		// First arg must be a string literal of the shape "METHOD /path".
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		raw, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		method, path := splitMethodPath(raw)
		if method == "" || path == "" {
			return true
		}
		auth := authForCall(call, path, server)
		handler, recvVar := "", ""
		if len(call.Args) > 1 {
			handler, recvVar = handlerName(call.Args[1])
		}
		*out = append(*out, httpRoute{
			Method:   method,
			Path:     path,
			Server:   server,
			AuthMode: auth,
			Pos:      lit.Pos(),
			Handler:  handler,
			Receiver: resolve(recvVar, call.Pos()),
			Dir:      relDir,
		})
		return true
	})
}

// compositeTypeName returns T for `&T{...}` or `T{...}`, else "".
func compositeTypeName(expr ast.Expr) string {
	if u, ok := expr.(*ast.UnaryExpr); ok && u.Op == token.AND {
		expr = u.X
	}
	cl, ok := expr.(*ast.CompositeLit)
	if !ok {
		return ""
	}
	if id, ok := cl.Type.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// handlerName resolves the handler method a registration names, looking
// through middleware wrappers: h.handleX, http.HandlerFunc(h.handleX),
// authMW.Wrap(http.HandlerFunc(h.handleX)), mw(h.handleX). It returns the
// method name and the receiver variable it is called on ("h"); the first
// selector whose name starts with "handle" wins, anything else yields "".
func handlerName(expr ast.Expr) (method, recv string) {
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		if strings.HasPrefix(e.Sel.Name, "handle") {
			if id, ok := e.X.(*ast.Ident); ok {
				return e.Sel.Name, id.Name
			}
			return e.Sel.Name, ""
		}
	case *ast.CallExpr:
		for _, a := range e.Args {
			if m, r := handlerName(a); m != "" {
				return m, r
			}
		}
	case *ast.ParenExpr:
		return handlerName(e.X)
	}
	return "", ""
}

// funcKey identifies a handler body by directory, receiver type and name.
// Plain functions have an empty receiver.
func funcKey(dir, recv, name string) string { return dir + "\x00" + recv + "\x00" + name }

// collectFuncs indexes every method and function declared in file by
// (dir, receiver type, name) so a route can find its handler body even
// when several handler types in one package share a method name.
func collectFuncs(file *ast.File, relDir string, out map[string]*ast.FuncDecl) {
	for _, d := range file.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		recv := ""
		if fd.Recv != nil && len(fd.Recv.List) == 1 {
			t := fd.Recv.List[0].Type
			if st, ok := t.(*ast.StarExpr); ok {
				t = st.X
			}
			if id, ok := t.(*ast.Ident); ok {
				recv = id.Name
			}
		}
		out[funcKey(relDir, recv, fd.Name.Name)] = fd
	}
}

// queryParams returns the sorted set of URL query parameter names the
// handler reads: string literals passed to .Get / .Has on a receiver that
// is r.URL.Query() itself or a variable holding it (q, query, params).
func queryParams(fd *ast.FuncDecl) []string {
	if fd.Body == nil {
		return nil
	}
	set := map[string]bool{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Get" && sel.Sel.Name != "Has") {
			return true
		}
		if !isQueryValues(sel.X) {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if name, err := strconv.Unquote(lit.Value); err == nil && name != "" {
			set[name] = true
		}
		return true
	})
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isQueryValues reports whether expr is r.URL.Query() or one of the
// conventional locals handlers assign it to.
func isQueryValues(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name == "q" || e.Name == "query" || e.Name == "params"
	case *ast.CallExpr:
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			return sel.Sel.Name == "Query"
		}
	}
	return false
}

// serverFromDir maps a route-source directory to the "public" / "admin"
// server label.
func serverFromDir(relDir string) string {
	if strings.HasPrefix(relDir, "api/admin") {
		return "admin"
	}
	return "public"
}

// splitMethodPath splits a Go 1.22 ServeMux pattern of the form
// "METHOD /path" into (method, path). Returns ("", "") on shapes that
// don't match (e.g. host-prefixed or no leading method).
func splitMethodPath(pattern string) (string, string) {
	parts := strings.SplitN(pattern, " ", 2)
	if len(parts) != 2 {
		return "", ""
	}
	m := strings.ToUpper(strings.TrimSpace(parts[0]))
	p := strings.TrimSpace(parts[1])
	if !strings.HasPrefix(p, "/") {
		return "", ""
	}
	switch m {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD":
		return m, p
	}
	return "", ""
}

// authForCall is a heuristic: returns "admin-api-key" for admin paths
// (every admin handler is wrapped with authMW.Wrap), "session" if the
// surrounding call wraps the handler with a SessionMiddleware-style
// .Wrap(...), else "none".
func authForCall(call *ast.CallExpr, path, server string) string {
	if server == "admin" {
		// /metrics is wrapped by promhttp BasicAuth not the admin API key.
		// Keep the heuristic conservative: every other admin path here
		// is authMW-wrapped (see api/admin/routes.go).
		if path == "/metrics" {
			return "metrics-basic-auth"
		}
		return "admin-api-key"
	}
	// Look at second arg (the handler) — if it's a CallExpr whose Fun
	// is a SelectorExpr with Sel.Name == "Wrap", the handler is
	// session-wrapped.
	if len(call.Args) < 2 {
		return "none"
	}
	if isSessionWrapped(call.Args[1]) {
		return "session"
	}
	return "none"
}

// isSessionWrapped returns true if expr is a call to .Wrap(...) — the
// common shape for SessionMiddleware-wrapped handlers in api/public.
func isSessionWrapped(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel.Name == "Wrap"
}

// collectDTOs walks file for `type Foo struct {...}` declarations whose
// fields carry `json:"..."` tags and appends one httpDTO per match. We
// only export DTOs whose top-level type name appears in a curated allow
// list ( so we don't drown the doc in helper structs) — actually we
// include every struct with at least one json-tagged field; the doc is
// long but uniform.
func collectDTOs(file *ast.File, relPath string, out *[]httpDTO) {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				continue
			}
			fields := []httpDTOField{}
			for _, f := range st.Fields.List {
				if f.Tag == nil {
					continue
				}
				tag, err := strconv.Unquote(f.Tag.Value)
				if err != nil {
					continue
				}
				st := reflect.StructTag(tag)
				jt := st.Get("json")
				if jt == "" || jt == "-" {
					continue
				}
				jsonName, omit := parseJSONTag(jt)
				if jsonName == "" {
					continue
				}
				typeStr := exprToTypeString(f.Type)
				required := !omit && !strings.HasPrefix(typeStr, "*")
				notes := ""
				if f.Doc != nil {
					notes = singleLine(f.Doc.Text())
				} else if f.Comment != nil {
					notes = singleLine(f.Comment.Text())
				}
				// One DTO field per name. Embedded struct fields with
				// multiple Names (rare here) emit one row per name.
				if len(f.Names) == 0 {
					fields = append(fields, httpDTOField{
						JSONName:  jsonName,
						Type:      typeStr,
						Required:  required,
						OmitEmpty: omit,
						Notes:     notes,
					})
					continue
				}
				for range f.Names {
					fields = append(fields, httpDTOField{
						JSONName:  jsonName,
						Type:      typeStr,
						Required:  required,
						OmitEmpty: omit,
						Notes:     notes,
					})
					// All names share the json tag in practice; only
					// emit one row to keep the table sane.
					break
				}
			}
			if len(fields) == 0 {
				continue
			}
			doc := ""
			if gen.Doc != nil {
				doc = singleLine(gen.Doc.Text())
			} else if ts.Doc != nil {
				doc = singleLine(ts.Doc.Text())
			}
			*out = append(*out, httpDTO{
				Name:     ts.Name.Name,
				Pos:      ts.Pos(),
				Fields:   fields,
				Comment:  doc,
				FilePath: relPath,
			})
		}
	}
}

// parseJSONTag splits a `json:"name,opts"` tag value into (name, omitempty).
func parseJSONTag(tag string) (string, bool) {
	parts := strings.Split(tag, ",")
	name := parts[0]
	omit := false
	for _, p := range parts[1:] {
		if strings.TrimSpace(p) == "omitempty" {
			omit = true
		}
	}
	return name, omit
}

// exprToTypeString renders an AST type expression as a compact
// Go-source-like string ("string", "[]ScopeView", "*time.Time",
// "map[string][]string", "json.RawMessage").
func exprToTypeString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		x := exprToTypeString(e.X)
		return x + "." + e.Sel.Name
	case *ast.StarExpr:
		return "*" + exprToTypeString(e.X)
	case *ast.ArrayType:
		return "[]" + exprToTypeString(e.Elt)
	case *ast.MapType:
		return "map[" + exprToTypeString(e.Key) + "]" + exprToTypeString(e.Value)
	case *ast.InterfaceType:
		return "any"
	}
	return "?"
}

// bareTypeName strips slice/pointer/map prefixes and selector prefix to
// the bare type identifier (e.g. "*[]admin.ScopeView" -> "ScopeView").
// Returns "" if the result is a builtin scalar.
func bareTypeName(t string) string {
	s := t
	for {
		switch {
		case strings.HasPrefix(s, "*"):
			s = s[1:]
		case strings.HasPrefix(s, "[]"):
			s = s[2:]
		case strings.HasPrefix(s, "map["):
			// "map[K]V" — take the value side.
			end := strings.Index(s, "]")
			if end < 0 {
				return ""
			}
			s = s[end+1:]
		default:
			goto done
		}
	}
done:
	if i := strings.LastIndex(s, "."); i >= 0 {
		s = s[i+1:]
	}
	switch s {
	case "string", "bool", "int", "int32", "int64", "uint", "uint32", "uint64",
		"float32", "float64", "any", "Time", "RawMessage", "Duration":
		return ""
	}
	return s
}

// -----------------------------------------------------------------------
// Rendering
// -----------------------------------------------------------------------

// renderHTTPDoc returns the full http-api.md document body.
func renderHTTPDoc(m *httpModel, repoRootPath string) string {
	src := srcref.New(m.FSet)

	var b strings.Builder
	b.WriteString(GeneratedByHeader)
	b.WriteString("\n\n")
	b.WriteString("# HTTP API Reference\n\n")
	b.WriteString(renderHTTPPreamble())
	b.WriteString("\n\n")

	// Index table.
	b.WriteString("## Index\n\n")
	idx := &mdwriter.Table{Headers: []string{"Method", "Path", "Server", "Section"}}
	for _, r := range m.Routes {
		anchor := routeAnchor(r)
		idx.Rows = append(idx.Rows, []string{
			"`" + r.Method + "`",
			"`" + r.Path + "`",
			r.Server,
			"[#" + anchor + "](#" + anchor + ")",
		})
	}
	b.WriteString(idx.Render())
	b.WriteString("\n")

	// Group routes by server for the per-route sections.
	publicRoutes, adminRoutes := partitionRoutesByServer(m.Routes)

	if len(publicRoutes) > 0 {
		b.WriteString("## Public API\n\n")
		for _, r := range publicRoutes {
			b.WriteString(renderRouteSection(r, src, repoRootPath))
		}
	}

	if len(adminRoutes) > 0 {
		b.WriteString("## Admin API\n\n")
		for _, r := range adminRoutes {
			b.WriteString(renderRouteSection(r, src, repoRootPath))
		}
	}

	// DTOs section.
	if len(m.DTOs) > 0 {
		b.WriteString("## DTOs\n\n")
		b.WriteString("The following DTOs are referenced from the endpoint sections above. ")
		b.WriteString("Field tables are derived directly from the Go struct tags in the ")
		b.WriteString("source files listed under each section — the OpenAPI YAML is *not* ")
		b.WriteString("ground truth (see `feedback_openapi_not_ground_truth`).\n\n")
		for _, d := range m.DTOs {
			b.WriteString(renderDTOSection(d, src, repoRootPath))
		}
	}

	return b.String()
}

// renderHTTPPreamble returns the static preamble paragraph(s) describing
// the two HTTP servers.
func renderHTTPPreamble() string {
	return "The Authplane authserver exposes two HTTP servers:\n\n" +
		"- **Public** (default `:9000`) — OAuth 2.1 endpoints, MCP discovery, " +
		"RFC-compliant well-known docs, the consent + login UI, and the " +
		"connect/disconnect surface for broker-vended upstreams.\n" +
		"- **Admin** (default `:9001`) — provisioning + day-2 operations, " +
		"protected by `Authorization: Bearer <AUTHPLANE_ADMIN_API_KEY>`. " +
		"The `/metrics` endpoint lives on the admin server and is gated by " +
		"Prometheus basic auth (see [Configuration](./configuration.md)).\n\n" +
		"All endpoints are documented from their route registration site in " +
		"`api/public/**` and `api/admin/**`; DTOs come from the Go struct tags " +
		"in `api/admin/dto.go`, `internal/admin/dto/dto.go`, `api/public/**/dto.go`, " +
		"and `api/shared/errors.go`. Sample shells live in `examples/` and the " +
		"[CLI reference](./cli.md) covers the matching `authserver admin …` " +
		"subcommands that round-trip the same wire shapes."
}

// partitionRoutesByServer returns (public, admin) preserving the input
// order within each bucket.
func partitionRoutesByServer(routes []httpRoute) ([]httpRoute, []httpRoute) {
	var pub, adm []httpRoute
	for _, r := range routes {
		if r.Server == "admin" {
			adm = append(adm, r)
		} else {
			pub = append(pub, r)
		}
	}
	return pub, adm
}

// renderRouteSection produces the H3 block for one HTTP route.
func renderRouteSection(r httpRoute, src *srcref.SrcRef, repoRootPath string) string {
	var b strings.Builder
	b.WriteString("### `")
	b.WriteString(r.Method)
	b.WriteString(" ")
	b.WriteString(r.Path)
	b.WriteString("`\n\n")
	b.WriteString(`<a id="`)
	b.WriteString(routeAnchor(r))
	b.WriteString("\"></a>\n\n")

	port := "9000"
	if r.Server == "admin" {
		port = "9001"
	}
	b.WriteString("**Server** — ")
	b.WriteString(r.Server)
	b.WriteString(" (:")
	b.WriteString(port)
	b.WriteString(")  \n")

	b.WriteString("**Auth** — ")
	switch r.AuthMode {
	case "admin-api-key":
		b.WriteString("`Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY`")
	case "session":
		b.WriteString("browser session cookie (managed by `shared.SessionMiddleware`)")
	case "metrics-basic-auth":
		b.WriteString("Prometheus basic-auth (see `metrics.basic_auth_*` config)")
	default:
		b.WriteString("none (public; request-body parameters identify the caller)")
	}
	b.WriteString("  \n")

	if ref := src.Format(r.Pos, repoRootPath); ref != "" {
		b.WriteString("**Source** — `")
		b.WriteString(ref)
		b.WriteString("`\n")
	}
	if len(r.Query) > 0 {
		b.WriteString("**Query** — ")
		for i, q := range r.Query {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString("`")
			b.WriteString(q)
			b.WriteString("`")
		}
		b.WriteString(" (read by `")
		b.WriteString(r.Handler)
		b.WriteString("`)\n")
	}
	b.WriteString("\n")

	// Per-endpoint request/response/error documentation is intentionally
	// minimal in the auto-generated form — the DTO tables below carry the
	// full field-level detail. The route section names the canonical DTOs
	// in human-readable form so the link to the DTO anchor is one click.
	if hint := routeBodyHint(r); hint != "" {
		b.WriteString(hint)
		b.WriteString("\n")
	}

	// Behavioral caveats that the DTO tables cannot express — cases where the
	// wire shape is correct but the server does something a reader would not
	// infer from it.
	if note := routeNotes[r.Method+" "+r.Path]; note != "" {
		b.WriteString("**Note** — ")
		b.WriteString(note)
		b.WriteString("\n\n")
	}

	b.WriteString("---\n\n")
	return b.String()
}

// routeBodyHint returns a short paragraph naming the canonical
// request/response DTO for a route, with anchor links into the DTO
// section. The mapping is hand-curated below and kept terse; the
// authoritative wire shape is the linked DTO table.
//
// DTO links inside each hint use a `{{dto:Name}}` placeholder that is
// expanded into a real anchor link via dtoAnchor() at render time. This
// keeps the canonical anchor-slug shape (with hyphens at CamelCase
// boundaries) the single source of truth — there is exactly one
// function that converts a Go type name to an anchor.
func routeBodyHint(r httpRoute) string {
	key := r.Method + " " + r.Path
	hint, ok := routeBodyHints[key]
	if !ok {
		return ""
	}
	return expandDTOLinks(hint)
}

// expandDTOLinks rewrites every `{{dto:Name}}` placeholder in s into a
// Markdown link of the form “[`Name`](#dto-name)“.
func expandDTOLinks(s string) string {
	var b strings.Builder
	for {
		start := strings.Index(s, "{{dto:")
		if start < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:start])
		end := strings.Index(s[start:], "}}")
		if end < 0 {
			b.WriteString(s[start:])
			return b.String()
		}
		name := s[start+len("{{dto:") : start+end]
		b.WriteString("[`")
		b.WriteString(name)
		b.WriteString("`](#")
		b.WriteString(dtoAnchor(name))
		b.WriteString(")")
		s = s[start+end+2:]
	}
}

// routeDescriptions maps "METHOD /path" → a prose statement of what the
// endpoint does, used only for the OpenAPI operation `description`. The
// Markdown reference already says this through routeBodyHints, but the OpenAPI
// projection consumes those structurally (requestBody/responses) rather than as
// prose — so an operation carrying a routeNotes caveat and nothing else reads
// as if the caveat were the endpoint's purpose. Add an entry when a route has a
// note whose opening sentence is not itself a statement about the endpoint.
// `POST /oauth/register` needs none: its note opens by saying what the endpoint
// creates.
var routeDescriptions = map[string]string{
	"POST /oauth/token": "Issues an access token for the grant named in `grant_type` " +
		"(RFC 6749 §3.2): `authorization_code`, `refresh_token`, `client_credentials`, " +
		"token-exchange and jwt-bearer. The request is form-encoded; DPoP-bound clients " +
		"send a `DPoP` header.",
}

// routeNotes maps "METHOD /path" → a behavioral caveat that the DTO tables
// cannot express: the wire shape is correct, but the server does something a
// reader would not infer from it. Rendered as a "**Note**" paragraph in the
// Markdown reference and as the operation `description` in the OpenAPI
// projection, so machine consumers (client codegen, Swagger UI) see it too.
// Keep entries to a short paragraph and name the remedy. A caveat belongs to
// the endpoint whose behavior it describes: when the cause and the effect sit
// on different routes, write a note on each and cross-reference by name rather
// than growing one of them.
var routeNotes = map[string]string{
	"POST /oauth/register": "this endpoint creates **user-delegated clients**. Their scopes " +
		"come from the user at consent time, so a `scope` member in the request is " +
		"**discarded** and the response carries none. **Register machine-to-machine clients " +
		"(`client_credentials`, jwt-bearer) with `POST /admin/clients` instead** — that is " +
		"the only surface that sets a client's scope ceiling, so a client registered here " +
		"starts without one and those two grants refuse every explicit `scope` at " +
		"`POST /oauth/token` with `invalid_scope`.",
	"POST /oauth/token": "`invalid_scope` on `client_credentials` or jwt-bearer usually " +
		"means an empty client ceiling: the client's registered `scope` is read only by " +
		"those two grants, and set only by the admin surface (`POST /admin/clients`, " +
		"`PATCH /admin/clients/{client_id}`).",
}

// routeBodyHints maps "METHOD /path" → a short Markdown paragraph
// linking the relevant DTO(s). Keep entries terse — the full wire shape
// lives in the DTO section.
var routeBodyHints = map[string]string{ //nolint:gosec // G101: literal example token in generated docs, not a real credential
	"POST /oauth/token": "**Request** — form-encoded `application/x-www-form-urlencoded`. " +
		"Grant params depend on `grant_type` (`authorization_code`, " +
		"`client_credentials`, `refresh_token`, `urn:ietf:params:oauth:grant-type:token-exchange`, " +
		"`urn:ietf:params:oauth:grant-type:jwt-bearer`). DPoP-bound clients " +
		"send `DPoP` header; the AS may answer with `WWW-Authenticate: DPoP error=\"use_dpop_nonce\"`.\n\n" +
		"**Response 200** — JSON {{dto:tokenResponseDTO}} or " +
		"{{dto:tokenExchangeResponseDTO}} for RFC 8693 exchanges.\n\n" +
		"**Errors** — RFC 6749 `invalid_request`, `invalid_client`, `invalid_grant`, " +
		"`unauthorized_client`, `unsupported_grant_type`, `invalid_scope`, plus " +
		"`consent_required` (with `consent_url`, see the prior-audit finding in " +
		"`api/shared/errors.go:36`). Body: {{dto:OAuthErrorResponse}}.\n",

	"POST /admin/clients": "**Request** — JSON {{dto:createClientRequest}}.\n\n" +
		"**Response 201** — JSON {{dto:createClientResponse}}; `client_secret` is shown ONCE.\n\n" +
		"**Errors** — 400 `invalid_request`, 401 `invalid_admin_key`, 409 `client_exists`.\n",

	"GET /admin/clients":                     "**Response 200** — JSON array of {{dto:clientView}}.\n",
	"GET /admin/clients/{id}":                "**Response 200** — JSON {{dto:clientView}}. 404 `client_not_found`.\n",
	"PATCH /admin/clients/{id}":              "**Request** — JSON {{dto:updateClientRequest}} (pointer fields → partial update). **Response 200** — {{dto:clientView}}.\n",
	"POST /admin/clients/{id}/rotate-secret": "**Response 200** — JSON {{dto:rotateSecretResponse}}; secret shown once.\n",
	"DELETE /admin/clients/{id}":             "**Response 204** — no body.\n",
	"PATCH /admin/clients/{id}/suspend":      "**Response 200** — JSON {{dto:statusResponse}}.\n",
	"PATCH /admin/clients/{id}/revoke":       "**Response 200** — JSON {{dto:statusResponse}}.\n",
	"PATCH /admin/clients/{id}/reactivate":   "**Response 200** — JSON {{dto:statusResponse}}.\n",

	"POST /admin/users":               "**Request** — JSON {{dto:createUserRequest}}. **Response 201** — {{dto:userView}}.\n",
	"GET /admin/users":                "**Response 200** — JSON array of {{dto:userView}}.\n",
	"GET /admin/users/{id}":           "**Response 200** — {{dto:userView}}.\n",
	"PATCH /admin/users/{id}":         "**Request** — JSON {{dto:updateUserRequest}}. **Response 200** — {{dto:userView}}.\n",
	"DELETE /admin/users/{id}":        "**Response 204** — no body.\n",
	"GET /admin/users/{id}/tokens":    "**Response 200** — `{ tokens: [...] }` (issuance summary; see `api/admin/handlers.go`).\n",
	"DELETE /admin/users/{id}/tokens": "**Response 200** — JSON `{ revoked: N }`.\n",
	"PATCH /admin/users/{id}/disable": "**Response 200** — JSON {{dto:statusResponse}}.\n",
	"PATCH /admin/users/{id}/enable":  "**Response 200** — JSON {{dto:statusResponse}}.\n",

	"POST /admin/resources":        "**Request** — JSON {{dto:createResourceRequest}}. **Response 201** — {{dto:ResourceView}}.\n",
	"GET /admin/resources":         "**Response 200** — JSON array of {{dto:ResourceView}}.\n",
	"GET /admin/resources/{id}":    "**Response 200** — {{dto:ResourceView}}.\n",
	"PATCH /admin/resources/{id}":  "**Request** — JSON {{dto:patchResourceRequest}}. **Response 200** — {{dto:ResourceView}}.\n",
	"DELETE /admin/resources/{id}": "**Response 204** — no body. 409 {{dto:frontingLinkConflictResponse}} if fronting links reference the resource without `?cascade=true`.\n",

	"POST /admin/broker-providers":        "**Request** — JSON {{dto:createBrokerProviderRequest}}. **Response 201** — {{dto:BrokerProviderView}}.\n",
	"GET /admin/broker-providers":         "**Response 200** — JSON array of {{dto:BrokerProviderView}}.\n",
	"GET /admin/broker-providers/{id}":    "**Response 200** — {{dto:BrokerProviderView}}.\n",
	"PATCH /admin/broker-providers/{id}":  "**Request** — JSON {{dto:patchBrokerProviderRequest}}. **Response 200** — {{dto:BrokerProviderView}}.\n",
	"DELETE /admin/broker-providers/{id}": "**Response 204** — no body.\n",

	"POST /admin/fronting":                     "**Request** — JSON {{dto:createFrontingLinkRequest}}; `?dry_run=true` validates without persisting. **Response 201** — {{dto:FrontingLinkView}}.\n",
	"GET /admin/fronting":                      "**Response 200** — JSON array of {{dto:FrontingLinkView}}.\n",
	"GET /admin/fronting/{source}/{target}":    "**Response 200** — {{dto:FrontingLinkView}}.\n",
	"PATCH /admin/fronting/{source}/{target}":  "**Request** — JSON {{dto:patchFrontingLinkRequest}}. **Response 200** — {{dto:FrontingLinkView}}.\n",
	"DELETE /admin/fronting/{source}/{target}": "**Response 204** — no body.\n",
	"GET /admin/resources/{slug}/fronting":     "**Response 200** — {{dto:ResourceFrontingView}} (split into `fronts` / `fronted_by`).\n",

	"GET /admin/issuances":         "**Response 200** — {{dto:IssuanceListResponse}}.\n",
	"GET /admin/issuances/{id}":    "**Response 200** — {{dto:IssuanceView}}.\n",
	"DELETE /admin/issuances/{id}": "**Response 204** — no body.\n",

	"GET /admin/users/{id}/grants":      "**Response 200** — {{dto:UserGrantsView}}. Note: `credential_data` is NEVER serialized on broker grants.\n",
	"DELETE /admin/grants/consent/{id}": "**Response 204** — no body.\n",
	"DELETE /admin/grants/broker/{id}":  "**Response 204** — no body.\n",

	"GET /admin/keys":         "**Response 200** — {{dto:listKeysResponse}}.\n",
	"POST /admin/keys/rotate": "**Response 200** — {{dto:rotateKeyResponse}}.\n",

	"GET /admin/settings/dcr":   "**Response 200** — {{dto:dcrSettingsView}}.\n",
	"PATCH /admin/settings/dcr": "**Request** — JSON {{dto:updateDCRSettingsRequest}}. **Response 200** — {{dto:dcrSettingsView}}.\n",

	"GET /admin/audit":         "**Response 200** — JSON array of {{dto:auditEventView}}.\n",
	"GET /admin/stats":         "**Response 200** — {{dto:statsView}}.\n",
	"POST /admin/auth/verify":  "**Response 200** — {{dto:authVerifyResponse}}.\n",
	"GET /admin/system/status": "**Response 200** — {{dto:systemStatusResponse}}.\n",
	"GET /admin/system/config": "**Response 200** — {{dto:systemConfigResponse}}.\n",

	"POST /oauth/register":   "**Request** — RFC 7591 client metadata JSON. **Response 201** — registered client metadata.\n",
	"POST /oauth/revoke":     "**Request** — form-encoded `token` + `token_type_hint`. **Response 200** — empty body (RFC 7009).\n",
	"POST /oauth/introspect": "**Request** — form-encoded `token`. **Response 200** — RFC 7662 introspection response.\n",
	"GET /oauth/authorize":   "Query-string parameters per RFC 6749 §4.1.1 + PKCE (`code_challenge`, `code_challenge_method=S256`). Redirects to `/consent` after login.\n",

	"GET /.well-known/jwks.json":                  "**Response 200** — JWKS document (public keys only). Cache-Control `max-age=300`.\n",
	"GET /.well-known/oauth-authorization-server": "**Response 200** — RFC 8414 metadata. Body shape: see `asMetadata` struct in `api/public/wellknown/dto.go`.\n",
	"GET /.well-known/openid-configuration":       "**Response 200** — same shape as the RFC 8414 endpoint.\n",
	"POST /login":                                 "**Response 303** — on success, redirects to the post-login target.\n\n**Response 404** — local password login is disabled (`oidc.show_local_login: false`). Answered before the body is read. `GET /login` still renders the page, without the password form.\n\n**Response 422** — the login page re-rendered with an error (bad form, bad CSRF nonce, rejected credential).\n\n**Response 429** — the submitted identity is locked out after `rate_limit.auth_fail_max` failures; carries `Retry-After` with the real remaining time. HTML, not an OAuth error body — the caller is a browser posting a form.\n",
	"GET /livez":                                  "**Response 200** — {{dto:healthResponse}}. Always 200 while the process serves HTTP; checks no dependencies, so a liveness probe on it never restarts a pod over a backend outage.\n",
	"GET /health":                                 "**Response 200** — {{dto:healthResponse}}.\n",
	"GET /ready":                                  "**Response 200** — {{dto:healthResponse}}.\n",
	"GET /metrics":                                "**Response 200** — Prometheus text-format metrics. Basic-auth protected.\n",
}

// routeAnchor returns the stable anchor slug for a route, e.g.
// `http-admin-resources-create`.
func routeAnchor(r httpRoute) string {
	prefix := "http-" + r.Server + "-"
	core := strings.TrimPrefix(r.Path, "/")
	// For admin paths, drop the redundant leading "admin/" so the anchor
	// reads "http-admin-resources-create" rather than
	// "http-admin-admin-resources-create".
	if r.Server == "admin" {
		core = strings.TrimPrefix(core, "admin/")
	}
	core = strings.ReplaceAll(core, "/", "-")
	core = strings.ReplaceAll(core, "{", "")
	core = strings.ReplaceAll(core, "}", "")
	core = strings.ReplaceAll(core, ".", "-")
	core = mdwriter.Slug(core)

	// Verb suffix (admin CRUD endpoints only — public discovery / OAuth
	// endpoints get just the path slug):
	//   POST collection              → -create
	//   GET  single (path ends {id}) → -get
	//   GET  collection              → -list
	//   PATCH / PUT                  → -update
	//   DELETE                       → -delete
	suffix := ""
	endsWithParam := strings.HasSuffix(r.Path, "}")
	if r.Server == "admin" {
		switch r.Method {
		case "POST":
			if !endsWithParam {
				suffix = "-create"
			}
		case "GET":
			if endsWithParam {
				suffix = "-get"
			} else {
				suffix = "-list"
			}
		case "PATCH", "PUT":
			suffix = "-update"
		case "DELETE":
			suffix = "-delete"
		}
	} else {
		// Public — paths can collide on method alone (GET/POST /login,
		// GET/POST /consent). Use a method-named suffix when the path
		// alone is ambiguous; leave canonical OAuth endpoints suffix-free
		// where the path already identifies the action.
		switch r.Method {
		case "DELETE":
			suffix = "-delete"
		case "POST":
			// Only suffix POST for paths that also bind GET on the same
			// shape; otherwise the bare path slug is fine.
			if r.Path == "/login" || r.Path == "/consent" || r.Path == "/logout" {
				suffix = "-post"
			}
		}
	}
	// Action endpoints (e.g. /rotate-secret, /suspend, /revoke,
	// /refresh-keys, /enable, /disable) already encode their verb in the
	// path; don't double-suffix in that case.
	last := lastSegment(r.Path)
	if isActionVerb(last) {
		suffix = ""
	}
	// /admin/auth/verify is a POST action endpoint — no -create suffix.
	if r.Path == "/admin/auth/verify" {
		suffix = ""
	}
	// /admin/keys/rotate.
	if strings.HasSuffix(r.Path, "/rotate") {
		suffix = ""
	}
	return prefix + core + suffix
}

// lastSegment returns the last "/"-separated segment of path.
func lastSegment(p string) string {
	idx := strings.LastIndex(p, "/")
	if idx < 0 {
		return p
	}
	return p[idx+1:]
}

// isActionVerb reports whether seg looks like an action verb a route
// path embeds in the URL (suspend, revoke, etc.). These paths are
// excluded from CRUD-suffix tagging.
func isActionVerb(seg string) bool {
	switch seg {
	case "rotate-secret", "suspend", "revoke", "reactivate", "disable",
		"enable", "refresh-keys", "rotate", "verify":
		return true
	}
	return false
}

// renderDTOSection produces the H3 block for one DTO.
func renderDTOSection(d httpDTO, src *srcref.SrcRef, repoRootPath string) string {
	var b strings.Builder
	b.WriteString("### `")
	b.WriteString(d.Name)
	b.WriteString("`\n\n")
	b.WriteString(`<a id="`)
	b.WriteString(dtoAnchor(d.Name))
	b.WriteString("\"></a>\n\n")
	if d.Comment != "" {
		b.WriteString(d.Comment)
		b.WriteString("\n\n")
	}
	if ref := src.Format(d.Pos, repoRootPath); ref != "" {
		b.WriteString("**Source** — `")
		b.WriteString(ref)
		b.WriteString("`\n\n")
	}

	t := &mdwriter.Table{Headers: []string{"Field", "Type", "Required", "Notes"}}
	for _, f := range d.Fields {
		req := "no"
		if f.Required {
			req = "yes"
		}
		typeCell := "`" + f.Type + "`"
		if f.RefDTO != "" {
			typeCell = typeCell + " → [`" + f.RefDTO + "`](#" + dtoAnchor(f.RefDTO) + ")"
		}
		notes := f.Notes
		if f.OmitEmpty && !strings.Contains(notes, "omitempty") {
			if notes != "" {
				notes = "`omitempty`. " + notes
			} else {
				notes = "`omitempty`"
			}
		}
		t.Rows = append(t.Rows, []string{"`" + f.JSONName + "`", typeCell, req, notes})
	}
	b.WriteString(t.Render())
	b.WriteString("\n")
	return b.String()
}

// dtoAnchor returns the stable anchor slug for a DTO name, e.g.
// `dto-create-resource-request`.
func dtoAnchor(name string) string {
	return "dto-" + camelToSlug(name)
}

// camelToSlug converts a Go identifier into a dashed lowercase slug.
// CamelCase boundaries get a "-"; runs of caps stay together (so
// "DCRSettings" → "dcrsettings", which matches Slug's collapse rules).
func camelToSlug(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			// Insert a dash only at a lower→upper boundary so DCRSettings
			// stays one segment.
			prev := rune(s[i-1])
			if prev >= 'a' && prev <= 'z' {
				b.WriteByte('-')
			}
		}
		if r >= 'A' && r <= 'Z' {
			r = r + ('a' - 'A')
		}
		b.WriteRune(r)
	}
	return mdwriter.Slug(b.String())
}
