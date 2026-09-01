package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNewEvent(t *testing.T) {
	e := NewEvent(ActionTokenIssued, "user-1", "client-1", "192.168.1.1", "issued access token")

	if e.Action != ActionTokenIssued {
		t.Errorf("Action = %q, want token.issued", e.Action)
	}
	if e.ActorID != "user-1" {
		t.Errorf("ActorID = %q, want user-1", e.ActorID)
	}
	if e.ClientID != "client-1" {
		t.Errorf("ClientID = %q, want client-1", e.ClientID)
	}
	if e.IP != "192.168.1.1" {
		t.Errorf("IP = %q, want 192.168.1.1", e.IP)
	}
	if e.Detail != "issued access token" {
		t.Errorf("Detail = %q", e.Detail)
	}
	// CreatedAt is left zero for the store to stamp. Replicas do not share a
	// clock; if NewEvent stamped one, a pod running slow would write rows behind
	// a cursor that had already read past them.
	if !e.CreatedAt.IsZero() {
		t.Errorf("CreatedAt = %v, want zero so the store stamps it", e.CreatedAt)
	}
}

// A caller may still place an event at a chosen time — backfill, import, tests.
// The store honors a non-zero value as given.
func TestEventCreatedAtIsAnExplicitOverride(t *testing.T) {
	at := time.Now().UTC().Add(-72 * time.Hour)
	e := NewEvent(ActionTokenIssued, "user-1", "client-1", "", "")
	e.CreatedAt = at
	if !e.CreatedAt.Equal(at) {
		t.Errorf("CreatedAt = %v, want the caller's %v", e.CreatedAt, at)
	}
}

// TestActionConstants reads every Action constant out of the package —
// every non-test file, both declaration forms (ActionX Action = "…" and
// ActionX = Action("…")) — so a constant added without touching this test
// is still covered: none may be empty, two constants may not share a
// string (two events would become indistinguishable in the audit log),
// and every value is lower-case dotted (`token.issued`,
// `resource.policy.created`) — the shape the docs and the admin audit
// filter assume. The scan is fail-closed: an Action*-named constant the
// scanner cannot decode fails the test instead of silently shrinking
// coverage.
func TestActionConstants(t *testing.T) {
	actions := actionConstantsFromSource(t)

	if _, ok := actions["ActionTokenIssued"]; !ok {
		t.Fatalf("parser found %d Action constants but not ActionTokenIssued — the scan is broken", len(actions))
	}

	valid := regexp.MustCompile(`^[a-z_]+(\.[a-z_]+)+$`)
	byValue := make(map[string]string, len(actions))
	for name, value := range actions {
		if value == "" {
			t.Errorf("%s is empty", name)
			continue
		}
		if !valid.MatchString(value) {
			t.Errorf("%s = %q, want lower-case dotted noun.verb", name, value)
		}
		if other, dup := byValue[value]; dup {
			t.Errorf("%s and %s both equal %q", name, other, value)
		}
		byValue[value] = name
	}
}

// actionConstantsFromSource returns name → string value for every Action
// constant declared in the package's non-test files, in either form:
//
//	ActionFoo Action = "foo.bar"   // typed
//	ActionFoo = Action("foo.bar")  // conversion
//
// Fail-closed: a constant that looks like an Action (typed, converted, or
// Action*-named) but cannot be decoded to a string literal is an error,
// never a silent skip.
func actionConstantsFromSource(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	out := make(map[string]string)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		collectActionConstants(t, f, out)
	}
	return out
}

// collectActionConstants adds f's Action constants to out.
func collectActionConstants(t *testing.T, f *ast.File, out map[string]string) {
	t.Helper()
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			typeIdent, _ := vs.Type.(*ast.Ident)
			typed := typeIdent != nil && typeIdent.Name == "Action"
			for i, name := range vs.Names {
				// Unwrap the conversion form Action("…") to its argument.
				var value ast.Expr
				converted := false
				if i < len(vs.Values) {
					value = vs.Values[i]
					if call, ok := value.(*ast.CallExpr); ok {
						if fn, ok := call.Fun.(*ast.Ident); ok && fn.Name == "Action" && len(call.Args) == 1 {
							value, converted = call.Args[0], true
						}
					}
				}
				if !typed && !converted && !strings.HasPrefix(name.Name, "Action") {
					continue // not an Action constant
				}
				if value == nil {
					t.Errorf("%s: no value of its own (const-block inheritance) — give every Action an explicit string", name.Name)
					continue
				}
				lit, ok := value.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Errorf("%s: not a plain string literal — use ActionX Action = %q or ActionX = Action(%q) so the scan covers it", name.Name, "noun.verb", "noun.verb")
					continue
				}
				str, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("%s: unquote %s: %v", name.Name, lit.Value, err)
				}
				out[name.Name] = str
			}
		}
	}
}
