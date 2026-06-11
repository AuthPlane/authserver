package configast

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"
)

// collectDefaults walks the DefaultConfig() function in loader.go
// and returns a YAML-path -> rendered-default lookup. It uses the
// struct map (Go-field-name -> YAML name + nested Go type) to
// resolve every KeyedElement in the composite literal exactly the
// way the YAML decoder would.
//
// Defaults are rendered as the operator would type them in YAML.
//
// Fields the DefaultConfig() literal doesn't set are absent from
// the returned map — the generators render those as `—`.
func collectDefaults(f *ast.File, structs map[string]*structInfo) map[string]string {
	out := map[string]string{}

	var fn *ast.FuncDecl
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fd.Name != nil && fd.Name.Name == "DefaultConfig" {
			fn = fd
			break
		}
	}
	if fn == nil {
		return out
	}

	// Locate the `return &Config{...}` composite literal.
	var rootLit *ast.CompositeLit
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			return true
		}
		unary, ok := ret.Results[0].(*ast.UnaryExpr)
		if !ok || unary.Op != token.AND {
			return true
		}
		cl, ok := unary.X.(*ast.CompositeLit)
		if !ok {
			return true
		}
		rootLit = cl
		return false
	})
	if rootLit == nil {
		return out
	}

	walkComposite(rootLit, "Config", "", structs, out)
	return out
}

// walkComposite recurses through a composite literal. For each
// KeyValueExpr it looks up the Go-field name in the struct map for
// the current type, extends the YAML dotted path with the field's
// YAML name, and either recurses (nested composite) or renders the
// scalar default.
func walkComposite(cl *ast.CompositeLit, typeName, prefix string, structs map[string]*structInfo, out map[string]string) {
	info := structs[typeName]
	yamlByGo := map[string]string{}
	typeByGo := map[string]string{}
	if info != nil {
		for _, fld := range info.fields {
			if fld.yamlName != "" {
				yamlByGo[fld.goName] = fld.yamlName
			}
			typeByGo[fld.goName] = strings.TrimPrefix(fld.goType, "[]")
		}
	}

	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		keyIdent, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		yamlSeg, ok := yamlByGo[keyIdent.Name]
		if !ok {
			// Field with no yaml tag (none in config.go today) —
			// skip silently.
			continue
		}
		path := yamlSeg
		if prefix != "" {
			path = prefix + "." + yamlSeg
		}

		switch v := kv.Value.(type) {
		case *ast.CompositeLit:
			walkComposite(v, typeByGo[keyIdent.Name], path, structs, out)
		default:
			if s := renderDefault(v); s != "" {
				out[path] = s
			}
		}
	}
}

// renderDefault prints an expression as the operator would write
// it in YAML. Unknown shapes return "" so the generator falls
// through to "—".
func renderDefault(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		switch v.Kind {
		case token.STRING:
			return strings.Trim(v.Value, "\"`")
		case token.INT, token.FLOAT:
			return v.Value
		}
	case *ast.Ident:
		switch v.Name {
		case "true", "false":
			return v.Name
		}
	case *ast.BinaryExpr:
		// Multiplication of an int literal by a time.* constant
		// — render as a Go duration string ("30s", "7h", etc).
		if d := renderDuration(v); d != "" {
			return d
		}
	case *ast.SelectorExpr:
		// time.Hour / time.Minute etc.
		if d := renderDurationIdent(v); d != "" {
			return d
		}
	}
	return ""
}

// renderDurationIdent handles bare `time.Hour`, `time.Minute`
// style values.
func renderDurationIdent(s *ast.SelectorExpr) string {
	pkg, ok := s.X.(*ast.Ident)
	if !ok || pkg.Name != "time" {
		return ""
	}
	switch s.Sel.Name {
	case "Nanosecond":
		return "1ns"
	case "Microsecond":
		return "1us"
	case "Millisecond":
		return "1ms"
	case "Second":
		return "1s"
	case "Minute":
		return "1m"
	case "Hour":
		return "1h"
	}
	return ""
}

// renderDuration handles `30 * time.Second`, `7 * 24 * time.Hour`,
// etc. Returns "" when the expression isn't a recognized duration
// shape.
func renderDuration(b *ast.BinaryExpr) string {
	if b.Op != token.MUL {
		return ""
	}
	mult, unit, ok := flattenMul(b)
	if !ok {
		return ""
	}
	switch unit {
	case "Nanosecond":
		return itoa64(mult) + "ns"
	case "Microsecond":
		return itoa64(mult) + "us"
	case "Millisecond":
		return itoa64(mult) + "ms"
	case "Second":
		return itoa64(mult) + "s"
	case "Minute":
		return itoa64(mult) + "m"
	case "Hour":
		return itoa64(mult) + "h"
	}
	return ""
}

// flattenMul walks a tree of `a * b * c` MUL expressions and
// returns (product-of-integers, name-of-time-unit). Exactly one
// time.X selector is expected somewhere in the chain.
func flattenMul(e ast.Expr) (int64, string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.INT {
			return 0, "", false
		}
		n, err := strconv.ParseInt(v.Value, 10, 64)
		if err != nil {
			return 0, "", false
		}
		return n, "", true
	case *ast.SelectorExpr:
		pkg, ok := v.X.(*ast.Ident)
		if !ok || pkg.Name != "time" {
			return 0, "", false
		}
		return 1, v.Sel.Name, true
	case *ast.BinaryExpr:
		if v.Op != token.MUL {
			return 0, "", false
		}
		lN, lU, lOk := flattenMul(v.X)
		rN, rU, rOk := flattenMul(v.Y)
		if !lOk || !rOk {
			return 0, "", false
		}
		unit := lU
		if unit == "" {
			unit = rU
		}
		if lN == 0 {
			lN = 1
		}
		if rN == 0 {
			rN = 1
		}
		return lN * rN, unit, true
	}
	return 0, "", false
}

// itoa64 is strconv.FormatInt for base 10.
func itoa64(n int64) string {
	return strconv.FormatInt(n, 10)
}
