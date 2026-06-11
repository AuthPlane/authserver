package configast

import (
	"go/ast"
	"go/token"
	"strings"
)

// envBinding is the internal representation of one AUTHPLANE_*
// binding captured from loader.go.
type envBinding struct {
	name     string    // "AUTHPLANE_SERVER_ISSUER"
	yamlPath string    // "server.issuer"
	helper   string    // "getEnv", "getEnvBool", ...
	pos      token.Pos // position of the call expression
}

// loaderHelpers lists the helper functions docsgen recognizes as
// env-var readers. The walker also matches os.Getenv / os.LookupEnv
// as a fallback for the (rare) direct env-var reads.
var loaderHelpers = map[string]bool{
	"getEnv":            true,
	"getEnvBool":        true,
	"getEnvInt":         true,
	"getEnvFloat64":     true,
	"getEnvDuration":    true,
	"getEnvStringSlice": true,
}

// collectEnvBindings walks loader.go and returns every recognized
// env-var binding. Each binding is captured at the call site, with
// its YAML path resolved from the receiver chain of the assignment
// the call participates in (or, for direct os.LookupEnv reads, from
// the call's surrounding statement).
//
// The walker is deliberately tolerant: a binding without a matching
// struct field still surfaces (with yamlPath==""), so reviewers can
// spot stray env reads in loader.go.
func collectEnvBindings(f *ast.File, structs map[string]*structInfo) []envBinding {
	var out []envBinding

	// Build a Go-name to YAML-name lookup keyed by struct type
	// so the walker can resolve "cfg.Server.Issuer" ->
	// "server.issuer" without needing types.Info.
	yamlByGoField := map[string]map[string]string{}
	goTypeByGoField := map[string]map[string]string{}
	for tyName, info := range structs {
		fm := map[string]string{}
		gm := map[string]string{}
		for _, fld := range info.fields {
			if fld.yamlName != "" {
				fm[fld.goName] = fld.yamlName
			}
			gm[fld.goName] = strings.TrimPrefix(fld.goType, "[]")
		}
		yamlByGoField[tyName] = fm
		goTypeByGoField[tyName] = gm
	}

	// Build a "section prefix" map keyed by Go type. Most loader
	// functions take a substruct (e.g. *ServerConfig) and assign
	// `cfg.Field = getEnv(...)`. The bindings need the parent
	// section's YAML name ("server.") prepended. We walk the
	// root Config struct once to discover which Go type maps to
	// which section. Types reachable through more than one field
	// (none today) keep the first-discovered prefix.
	sectionByType := map[string]string{}
	if root, ok := structs["Config"]; ok {
		for _, fld := range root.fields {
			if fld.yamlName == "" {
				continue
			}
			ty := strings.TrimPrefix(fld.goType, "[]")
			if _, exists := sectionByType[ty]; !exists {
				sectionByType[ty] = fld.yamlName
			}
		}
	}
	// Config itself: no prefix.
	sectionByType["Config"] = ""

	// Walk every function and track the receiver-type of `cfg`
	// (the conventional loader argument name) so we can resolve
	// "cfg.Server.Issuer" against the Config struct.
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		// Recover the type of `cfg` from the first parameter.
		cfgType := loaderCfgParamType(fn)

		// Inside the function body look for assignments like
		// cfg.X.Y = getEnv("AUTHPLANE_...", cfg.X.Y).
		ast.Inspect(fn.Body, func(stmt ast.Node) bool {
			as, ok := stmt.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return true
			}
			call, ok := as.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			helper := callHelperName(call)
			if helper == "" {
				return true
			}
			envName := stringLitArg(call, 0)
			if envName == "" || !strings.HasPrefix(envName, "AUTHPLANE_") {
				return true
			}
			yamlPath := resolveSelectorPath(as.Lhs[0], cfgType, yamlByGoField, goTypeByGoField)
			if prefix := sectionByType[cfgType]; prefix != "" && yamlPath != "" {
				yamlPath = prefix + "." + yamlPath
			}
			out = appendUnique(out, envBinding{
				name:     envName,
				yamlPath: yamlPath,
				helper:   helper,
				pos:      call.Pos(),
			})
			return true
		})

		// Also catch standalone `getEnv("AUTHPLANE_...", "")`
		// calls that do not assign back to a struct field (used
		// for the broker-provider single-instance seed and the
		// resource URI seed). These have no YAML path; record
		// them anyway so the env-vars.md table is complete.
		ast.Inspect(fn.Body, func(stmt ast.Node) bool {
			call, ok := stmt.(*ast.CallExpr)
			if !ok {
				return true
			}
			// Skip the calls already captured via assignment.
			// We pick them up by looking at their parent —
			// but since ast.Inspect doesn't give a parent
			// cheaply, we de-dup on (name, pos) after the
			// full sweep.
			helper := callHelperName(call)
			if helper == "" {
				return true
			}
			envName := stringLitArg(call, 0)
			if envName == "" || !strings.HasPrefix(envName, "AUTHPLANE_") {
				return true
			}
			out = appendUnique(out, envBinding{
				name:   envName,
				helper: helper,
				pos:    call.Pos(),
			})
			return true
		})
		return true
	})

	return out
}

// appendUnique de-dupes by env-var name. The first occurrence
// wins; a later getEnv()/os.LookupEnv() pair for the same name
// (as happens in loadBrokerProviderFromEnv) is dropped so the
// env-vars.md table lists each name exactly once.
func appendUnique(out []envBinding, b envBinding) []envBinding {
	for _, prev := range out {
		if prev.name == b.name {
			return out
		}
	}
	return append(out, b)
}

// loaderCfgParamType returns the type-name of the function's first
// pointer-parameter (e.g. "ServerConfig" for func loadServerFromEnv(cfg *ServerConfig)).
// Returns "" when the function has no pointer-receiver-style param,
// which is fine — the binding's YAML path simply won't resolve.
func loaderCfgParamType(fn *ast.FuncDecl) string {
	if fn.Type == nil || fn.Type.Params == nil || len(fn.Type.Params.List) == 0 {
		return ""
	}
	first := fn.Type.Params.List[0]
	star, ok := first.Type.(*ast.StarExpr)
	if !ok {
		return ""
	}
	id, ok := star.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return id.Name
}

// callHelperName returns the helper-function name (e.g. "getEnv")
// or "" if the call isn't a recognized env reader.
func callHelperName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		if loaderHelpers[fn.Name] {
			return fn.Name
		}
	case *ast.SelectorExpr:
		// os.LookupEnv / os.Getenv.
		x, _ := fn.X.(*ast.Ident)
		if x != nil && x.Name == "os" {
			if fn.Sel.Name == "LookupEnv" || fn.Sel.Name == "Getenv" {
				return "os." + fn.Sel.Name
			}
		}
	}
	return ""
}

// stringLitArg returns the literal string value of call.Args[i],
// stripped of surrounding quotes. Returns "" when the arg is
// missing or not a basic string literal.
func stringLitArg(call *ast.CallExpr, i int) string {
	if i >= len(call.Args) {
		return ""
	}
	bl, ok := call.Args[i].(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return ""
	}
	return strings.Trim(bl.Value, "\"`")
}

// resolveSelectorPath walks a chain like `cfg.Server.Issuer` and
// emits the corresponding YAML dotted path ("server.issuer"). The
// outermost identifier (cfg) is dropped; each subsequent selector
// is resolved through yamlByGoField using the type of the receiver
// at that position (which we track via goTypeByGoField).
//
// Returns "" when any step doesn't resolve.
func resolveSelectorPath(lhs ast.Expr, rootType string, yamlByGoField, goTypeByGoField map[string]map[string]string) string {
	// Collect the selector chain in source order (Server.Issuer).
	chain := []string{}
	cur := lhs
	for {
		sel, ok := cur.(*ast.SelectorExpr)
		if !ok {
			break
		}
		chain = append([]string{sel.Sel.Name}, chain...)
		cur = sel.X
	}
	if len(chain) == 0 {
		return ""
	}
	// The outermost identifier (cfg) is dropped — its type is
	// rootType. Walk the chain top-down.
	tyName := rootType
	var pathSegments []string
	for _, seg := range chain {
		fields := yamlByGoField[tyName]
		if fields == nil {
			return ""
		}
		yamlSeg, ok := fields[seg]
		if !ok {
			return ""
		}
		pathSegments = append(pathSegments, yamlSeg)
		// Advance the type pointer for the next hop.
		if next := goTypeByGoField[tyName][seg]; next != "" {
			tyName = next
		}
	}
	return strings.Join(pathSegments, ".")
}
