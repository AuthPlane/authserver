package configast

import (
	"go/ast"
	"reflect"
	"strings"
)

// extractYAMLTag pulls the yaml:"..." struct-tag and splits it into
// the leading name and any comma-separated options. A missing tag
// returns ("", nil).
func extractYAMLTag(tag *ast.BasicLit) (string, []string) {
	if tag == nil {
		return "", nil
	}
	// Trim the surrounding backticks before reflect.StructTag.
	raw := strings.Trim(tag.Value, "`")
	val, ok := reflect.StructTag(raw).Lookup("yaml")
	if !ok {
		return "", nil
	}
	parts := strings.Split(val, ",")
	if len(parts) == 0 {
		return "", nil
	}
	return strings.TrimSpace(parts[0]), parts[1:]
}

// renderType prints an *ast.Expr (the type half of a field) as the
// Go source spelling: "string", "time.Duration", "[]string",
// "map[string]interface{}", "ServerConfig", "*int". The walker
// strips pointers because no config field is a pointer today;
// future fields will still render readably.
func renderType(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		x, _ := t.X.(*ast.Ident)
		if x == nil {
			return t.Sel.Name
		}
		return x.Name + "." + t.Sel.Name
	case *ast.ArrayType:
		return "[]" + renderType(t.Elt)
	case *ast.MapType:
		return "map[" + renderType(t.Key) + "]" + renderType(t.Value)
	case *ast.StarExpr:
		return "*" + renderType(t.X)
	case *ast.InterfaceType:
		// Empty interface ("any") shows up as interface{} in older
		// code; print it back as "interface{}" for consistency.
		return "interface{}"
	}
	return ""
}

// normaliseType maps the Go spelling to a friendlier docs string:
// time.Duration -> duration, float64 -> float64, []string stays as
// []string. Anything we don't have a friendlier name for is
// returned unchanged so reviewers can spot drift.
func normaliseType(goType string) string {
	switch goType {
	case "time.Duration":
		return "duration"
	case "string", "bool", "int", "float64":
		return goType
	case "[]string":
		return "[]string"
	case "map[string]interface{}":
		return "map"
	case "interface{}":
		return "any"
	}
	// Slices of structs: render as []T so the docs still say
	// "list of T" without leaking the package prefix.
	if strings.HasPrefix(goType, "[]") {
		return goType
	}
	return goType
}

// cleanComment normalises a doc-comment group: removes leading
// "//" / "/*" markers, joins multi-line comments with single
// spaces, and trims surrounding whitespace.
func cleanComment(g *ast.CommentGroup) string {
	if g == nil {
		return ""
	}
	var b strings.Builder
	for i, c := range g.List {
		text := c.Text
		text = strings.TrimPrefix(text, "//")
		text = strings.TrimPrefix(text, "/*")
		text = strings.TrimSuffix(text, "*/")
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		if i > 0 {
			b.WriteString(" ")
		}
		b.WriteString(text)
	}
	return strings.TrimSpace(b.String())
}

// pickFieldComment prefers the trailing-line comment ("// foo") on
// a field declaration over the leading doc-comment because that's
// the dominant style in internal/config/config.go. Falls back to
// the leading doc-comment when no trailing comment exists.
func pickFieldComment(f *ast.Field) string {
	if c := cleanComment(f.Comment); c != "" {
		return c
	}
	return cleanComment(f.Doc)
}
