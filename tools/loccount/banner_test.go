package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBannerRender(t *testing.T) {
	b := BannerData{AuthLines: 4, TotalLines: 42, SDKVersion: "go-sdk v1.2.3"}
	got := b.Render()
	want := "<!-- loccount:begin -->\n**Auth-specific code: 4 lines · Total example: 42 lines · SDK: go-sdk v1.2.3**\n<!-- loccount:end -->"
	if got != want {
		t.Fatalf("Render mismatch:\n got=%q\nwant=%q", got, want)
	}
}

func TestBannerRenderEmptySDK(t *testing.T) {
	b := BannerData{AuthLines: 0, TotalLines: 0, SDKVersion: ""}
	if !strings.Contains(b.Render(), "SDK: (none)") {
		t.Fatalf("empty SDK should render as (none): %s", b.Render())
	}
}

func TestApplyBanner_InsertAfterH1(t *testing.T) {
	readme := "# My Example\n\nSome description.\n"
	out, changed := applyBanner(readme, BannerData{AuthLines: 3, TotalLines: 10, SDKVersion: "go-sdk v1"})
	if !changed {
		t.Fatal("expected changed=true on first insert")
	}
	if !strings.Contains(out, "<!-- loccount:begin -->") {
		t.Fatalf("banner missing in output: %s", out)
	}
	if !strings.HasPrefix(out, "# My Example\n\n<!-- loccount:begin -->") {
		t.Fatalf("banner not placed right after H1: %s", out)
	}
}

func TestApplyBanner_InsertAtTopWhenNoH1(t *testing.T) {
	readme := "Plain text with no heading.\n"
	out, changed := applyBanner(readme, BannerData{AuthLines: 1, TotalLines: 2, SDKVersion: "(none)"})
	if !changed {
		t.Fatal("expected changed")
	}
	if !strings.HasPrefix(out, "<!-- loccount:begin -->") {
		t.Fatalf("banner should be at top: %s", out)
	}
}

func TestApplyBanner_Idempotent(t *testing.T) {
	readme := "# Heading\n\nBody.\n"
	bd := BannerData{AuthLines: 7, TotalLines: 20, SDKVersion: "ts-sdk 1.0.0"}
	first, changed1 := applyBanner(readme, bd)
	if !changed1 {
		t.Fatal("first pass should change")
	}
	second, changed2 := applyBanner(first, bd)
	if changed2 {
		t.Fatalf("second pass should be idempotent; diff:\nfirst=%q\nsecond=%q", first, second)
	}
	if first != second {
		t.Fatalf("idempotency broken")
	}
	// Third pass for good measure.
	third, changed3 := applyBanner(second, bd)
	if changed3 || third != second {
		t.Fatalf("third pass not idempotent")
	}
}

func TestApplyBanner_UpdatesStaleNumbers(t *testing.T) {
	readme := "# X\n\n<!-- loccount:begin -->\n**Auth-specific code: 999 lines · Total example: 999 lines · SDK: (none)**\n<!-- loccount:end -->\n\nRest.\n"
	out, changed := applyBanner(readme, BannerData{AuthLines: 1, TotalLines: 2, SDKVersion: "(none)"})
	if !changed {
		t.Fatal("stale banner should be detected as change")
	}
	if strings.Contains(out, "999") {
		t.Fatalf("stale numbers leaked: %s", out)
	}
	if !strings.Contains(out, "Auth-specific code: 1 lines") {
		t.Fatalf("new numbers missing: %s", out)
	}
}

func TestExtractBanner(t *testing.T) {
	readme := "# X\n\n<!-- loccount:begin -->\n**Auth-specific code: 3 lines · Total example: 9 lines · SDK: (none)**\n<!-- loccount:end -->\n"
	got := extractBanner(readme)
	if !strings.Contains(got, "Auth-specific code: 3") {
		t.Fatalf("extractBanner missed content: %q", got)
	}
	if extractBanner("# No banner here") != "" {
		t.Fatal("expected empty extraction")
	}
}

// TestEndToEnd_BannerRegenerationIdempotent verifies the full flow:
// build an example dir with a marked Go file and a README, run the
// analyzer twice in --regenerate-banner mode, and assert no diff.
func TestEndToEnd_BannerRegenerationIdempotent(t *testing.T) {
	dir := t.TempDir()
	ex := filepath.Join(dir, "examples", "foo", "01-basic")
	if err := os.MkdirAll(ex, 0o755); err != nil {
		t.Fatal(err)
	}
	goSrc := `package main

import "fmt"

// authplane:begin
fmt.Println("hi")
doStuff()
// authplane:end
`
	if err := os.WriteFile(filepath.Join(ex, "main.go"), []byte(goSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ex, "README.md"), []byte("# Basic\n\nIntro.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	budgets := Budgets{Tiers: map[string]int{"01": 5}}

	r1, err := analyzeExample(ex, budgets, runOptions{Regenerate: true})
	if err != nil {
		t.Fatalf("first analyze: %v", err)
	}
	if r1.AuthLines != 2 {
		t.Fatalf("AuthLines=%d want 2", r1.AuthLines)
	}
	if r1.Tier != "01" {
		t.Fatalf("tier=%q want 01", r1.Tier)
	}
	first, err := os.ReadFile(filepath.Join(ex, "README.md"))
	if err != nil {
		t.Fatal(err)
	}

	// Second run, should make no changes.
	r2, err := analyzeExample(ex, budgets, runOptions{Regenerate: true})
	if err != nil {
		t.Fatalf("second analyze: %v", err)
	}
	if r2.BannerStale {
		t.Fatal("banner should not be stale on second run")
	}
	second, err := os.ReadFile(filepath.Join(ex, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("README changed on second run:\nfirst=%q\nsecond=%q", first, second)
	}
}

// TestEndToEnd_CheckDetectsStale ensures that without --regenerate-banner
// the analyzer still reports BannerStale=true when the README is out of date.
func TestEndToEnd_CheckDetectsStale(t *testing.T) {
	dir := t.TempDir()
	ex := filepath.Join(dir, "examples", "foo", "02-stale")
	if err := os.MkdirAll(ex, 0o755); err != nil {
		t.Fatal(err)
	}
	goSrc := `package main

// authplane:begin
a := 1
b := 2
c := 3
// authplane:end
`
	if err := os.WriteFile(filepath.Join(ex, "main.go"), []byte(goSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	// Banner present but with wrong numbers.
	readme := "# Stale\n\n<!-- loccount:begin -->\n**Auth-specific code: 99 lines · Total example: 99 lines · SDK: (none)**\n<!-- loccount:end -->\n\nBody.\n"
	if err := os.WriteFile(filepath.Join(ex, "README.md"), []byte(readme), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := analyzeExample(ex, Budgets{Tiers: map[string]int{"02": 8}}, runOptions{Regenerate: false})
	if err != nil {
		t.Fatal(err)
	}
	if !r.BannerStale {
		t.Fatalf("expected BannerStale=true, got %+v", r)
	}
	// Without --regenerate-banner the file must not be touched.
	after, _ := os.ReadFile(filepath.Join(ex, "README.md"))
	if string(after) != readme {
		t.Fatalf("README was modified without --regenerate-banner")
	}
}

func TestEndToEnd_BudgetEnforcement(t *testing.T) {
	dir := t.TempDir()
	ex := filepath.Join(dir, "examples", "foo", "01-fat")
	if err := os.MkdirAll(ex, 0o755); err != nil {
		t.Fatal(err)
	}
	// Generate ~10 auth lines, budget is 5.
	var sb strings.Builder
	sb.WriteString("package main\n\n// authplane:begin\n")
	for i := 0; i < 10; i++ {
		sb.WriteString("x := 1\n")
	}
	sb.WriteString("// authplane:end\n")
	if err := os.WriteFile(filepath.Join(ex, "main.go"), []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ex, "README.md"), []byte("# Fat\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := analyzeExample(ex, Budgets{Tiers: map[string]int{"01": 5}}, runOptions{Regenerate: false})
	if err != nil {
		t.Fatal(err)
	}
	if !r.OverBudget {
		t.Fatalf("expected OverBudget=true (auth=%d budget=%d)", r.AuthLines, r.Budget)
	}
}

func TestDetectSDK(t *testing.T) {
	dir := t.TempDir()
	// go.mod with our SDK pin
	gomod := "module x\n\ngo 1.21\n\nrequire github.com/authplane/go-sdk v1.2.3\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := detectSDK(dir); got != "go-sdk v1.2.3" {
		t.Fatalf("detectSDK go.mod got %q", got)
	}

	dir2 := t.TempDir()
	pkg := `{"dependencies":{"@authplane/sdk":"^2.0.1"}}`
	if err := os.WriteFile(filepath.Join(dir2, "package.json"), []byte(pkg), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := detectSDK(dir2); got != "ts-sdk ^2.0.1" {
		t.Fatalf("detectSDK node got %q", got)
	}

	dir3 := t.TempDir()
	if got := detectSDK(dir3); got != "(none)" {
		t.Fatalf("detectSDK empty got %q", got)
	}

	dir4 := t.TempDir()
	pyproj := `[project]
dependencies = ["authplane-sdk==3.4.5"]
`
	if err := os.WriteFile(filepath.Join(dir4, "pyproject.toml"), []byte(pyproj), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := detectSDK(dir4); !strings.HasPrefix(got, "python-sdk ") {
		t.Fatalf("detectSDK python got %q", got)
	}
}

func TestLoadBudgets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "b.yaml")
	body := "tiers:\n  \"01\": 5\n  \"02\": 8\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := loadBudgets(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tiers["01"] != 5 || got.Tiers["02"] != 8 {
		t.Fatalf("budgets wrong: %+v", got)
	}

	// Missing file path -> empty budgets, no error.
	got2, err := loadBudgets("")
	if err != nil {
		t.Fatal(err)
	}
	_ = got2
}
