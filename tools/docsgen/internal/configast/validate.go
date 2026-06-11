package configast

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"
)

// requiredRegexp matches an error message of the shape
// `<dotted.path> is required when <condition>`. Validate.go uses
// this phrasing for every conditional-required rule, so the
// walker can reliably extract the (path, condition) pair without
// modeling validate.go's branching.
var requiredRegexp = regexp.MustCompile(`^([a-z][a-z_0-9.]+(?:\.[a-z][a-z_0-9]+)+)\s+is required when\s+(.+?)$`)

// collectRequiredWhen scans every string literal in validate.go
// and returns a YAML-path -> condition lookup. When the same path
// has multiple rules, the entries are joined by "; " in source
// order so the docs surface both predicates ("oidc is enabled" and
// "X is set", etc).
func collectRequiredWhen(f *ast.File) map[string]string {
	out := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		bl, ok := n.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return true
		}
		text := strings.Trim(bl.Value, "\"`")
		text = strings.TrimSuffix(text, ".") // strip a trailing period
		// Validate.go phrases vault_transit_encrypt rules as
		// `field is required when driver is vault_transit_encrypt`
		// which fits the same regex.
		if m := requiredRegexp.FindStringSubmatch(text); m != nil {
			path := m[1]
			cond := strings.TrimSpace(m[2])
			if existing, ok := out[path]; ok && !strings.Contains(existing, cond) {
				out[path] = existing + "; " + cond
			} else {
				out[path] = cond
			}
		}
		return true
	})
	return out
}
