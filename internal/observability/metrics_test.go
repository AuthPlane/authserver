package observability

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// instrumentConstructors are the otel meter methods metrics.go registers
// instruments through. The first argument to each is the instrument name.
var instrumentConstructors = map[string]bool{
	"Int64Counter":       true,
	"Int64UpDownCounter": true,
	"Float64Histogram":   true,
}

// registeredInstrumentNames parses metrics.go and returns every instrument
// name string handed to a meter constructor, in source order. Parsing the
// source rather than exercising a reader keeps the check independent of
// which provider is wired, and catches an instrument that is registered
// but never assigned to a field.
func registeredInstrumentNames(t *testing.T) []string {
	t.Helper()

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "metrics.go", nil, 0)
	if err != nil {
		t.Fatalf("parse metrics.go: %v", err)
	}

	var names []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !instrumentConstructors[sel.Sel.Name] || len(call.Args) == 0 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			t.Errorf("%s: %s called with a non-literal instrument name; the doc check needs a string literal",
				fset.Position(call.Pos()), sel.Sel.Name)
			return true
		}
		name, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatalf("%s: unquote %s: %v", fset.Position(lit.Pos()), lit.Value, err)
		}
		names = append(names, name)
		return true
	})
	return names
}

// Every exported instrument on Metrics must be populated by newMetrics. A
// nil instrument is not a startup failure: the emit sites call Add/Record
// on it unguarded, so a forgotten assignment surfaces as a panic on the
// first request that reaches that code path.
func TestNewMetrics_EveryExportedFieldIsNonNil(t *testing.T) {
	m, err := newMetrics(NewNoopMeter())
	if err != nil {
		t.Fatalf("newMetrics: %v", err)
	}

	v := reflect.ValueOf(m).Elem()
	typ := v.Type()
	var checked int
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		checked++
		if v.Field(i).IsNil() {
			t.Errorf("Metrics.%s is nil after newMetrics", field.Name)
		}
	}
	if checked == 0 {
		t.Fatal("no exported fields found on Metrics; the reflection walk is broken")
	}

	// The noop provider used across the test suite must be constructed the
	// same way, or a service test could pass against nil instruments that
	// the real provider would populate.
	noop := NewNoop().Metrics
	nv := reflect.ValueOf(noop).Elem()
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).IsExported() && nv.Field(i).IsNil() {
			t.Errorf("NewNoop().Metrics.%s is nil", typ.Field(i).Name)
		}
	}
}

// One registration per exported field, and the names are unique. Two
// fields registered under the same name would silently share a series;
// a field with no registration would be caught by the nil check above,
// but a registration with no field would be invisible to it.
func TestMetrics_RegistrationsMatchFields(t *testing.T) {
	names := registeredInstrumentNames(t)

	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if seen[n] {
			t.Errorf("instrument %q is registered more than once", n)
		}
		seen[n] = true
	}

	typ := reflect.TypeOf(Metrics{})
	var exported int
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).IsExported() {
			exported++
		}
	}
	if len(names) != exported {
		t.Errorf("metrics.go registers %d instruments but Metrics has %d exported fields", len(names), exported)
	}
}

// docs/reference/metrics.md is hand-maintained. Every registered instrument
// name must have a row there, so an operator reading the reference sees
// the full set the server exports.
func TestMetrics_EveryInstrumentIsDocumented(t *testing.T) {
	docPath := filepath.Join("..", "..", "docs", "reference", "metrics.md")
	raw, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}
	doc := string(raw)

	names := registeredInstrumentNames(t)
	if len(names) == 0 {
		t.Fatal("no instrument registrations found in metrics.go")
	}

	var missing []string
	for _, name := range names {
		// Rows quote the name in backticks; require the exact cell so a
		// prefix match (e.g. tokens_issued vs tokens_issued_total) cannot
		// satisfy the check.
		if !strings.Contains(doc, fmt.Sprintf("| `%s` |", name)) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("instruments registered in metrics.go with no row in %s:\n  %s",
			docPath, strings.Join(missing, "\n  "))
	}
}
