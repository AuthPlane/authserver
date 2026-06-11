package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Budgets maps a tier identifier (the two-digit prefix of an example
// directory, e.g. "01") to the maximum number of auth-specific lines
// allowed for that tier.
type Budgets struct {
	Tiers map[string]int `yaml:"tiers"`
}

// ExampleReport is the per-example summary surfaced via --json and
// printed in human-friendly form by default.
type ExampleReport struct {
	Path        string `json:"path"`
	Tier        string `json:"tier"`
	AuthLines   int    `json:"auth_lines"`
	TotalLines  int    `json:"total_lines"`
	SDKVersion  string `json:"sdk_version"`
	Budget      int    `json:"budget,omitempty"`
	OverBudget  bool   `json:"over_budget,omitempty"`
	BannerStale bool   `json:"banner_stale,omitempty"`
}

func main() {
	var (
		regenerate = flag.Bool("regenerate-banner", false, "rewrite the loccount banner in each example's README.md")
		check      = flag.Bool("check", false, "exit 1 if any banner is stale")
		budgetFlag = flag.Bool("budget", false, "exit 1 if any example exceeds its tier budget")
		jsonFlag   = flag.Bool("json", false, "emit JSON instead of human text")
		budgetFile = flag.String("budgets", "", "path to budgets.yaml (default: alongside the binary's source)")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: loccount [flags] [DIR...]\n\n")
		fmt.Fprintf(os.Stderr, "If no DIR is provided, walks examples/*/*/ from the current working directory.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if err := run(flag.Args(), runOptions{
		Regenerate: *regenerate,
		Check:      *check,
		Budget:     *budgetFlag,
		JSON:       *jsonFlag,
		BudgetFile: *budgetFile,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "loccount: "+err.Error())
		os.Exit(1)
	}
}

type runOptions struct {
	Regenerate bool
	Check      bool
	Budget     bool
	JSON       bool
	BudgetFile string
}

func run(dirs []string, opts runOptions) error {
	if len(dirs) == 0 {
		discovered, err := discoverExamples(".")
		if err != nil {
			return fmt.Errorf("discover examples: %w", err)
		}
		dirs = discovered
	}

	budgets, err := loadBudgets(opts.BudgetFile)
	if err != nil {
		return fmt.Errorf("load budgets: %w", err)
	}

	reports := make([]ExampleReport, 0, len(dirs))
	var staleExamples []string
	var overBudget []string

	for _, dir := range dirs {
		report, err := analyzeExample(dir, budgets, opts)
		if err != nil {
			return fmt.Errorf("analyze %s: %w", dir, err)
		}
		reports = append(reports, report)
		if report.BannerStale {
			staleExamples = append(staleExamples, dir)
		}
		if report.OverBudget {
			overBudget = append(overBudget, dir)
		}
	}

	if opts.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			return err
		}
	} else {
		printHuman(reports)
	}

	if opts.Check && len(staleExamples) > 0 {
		fmt.Fprintf(os.Stderr, "stale banners in: %s\n", strings.Join(staleExamples, ", "))
		os.Exit(1)
	}
	if opts.Budget && len(overBudget) > 0 {
		fmt.Fprintf(os.Stderr, "over budget: %s\n", strings.Join(overBudget, ", "))
		os.Exit(1)
	}
	return nil
}

// discoverExamples walks `examples/*/*/` relative to root and returns the
// matched directories in sorted order.
func discoverExamples(root string) ([]string, error) {
	base := filepath.Join(root, "examples")
	entries, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub, err := os.ReadDir(filepath.Join(base, e.Name()))
		if err != nil {
			return nil, err
		}
		for _, se := range sub {
			if !se.IsDir() {
				continue
			}
			// Only consider dirs whose basename matches the tier prefix
			// (`NN-...`). Skips legacy non-tiered example trees (e.g.
			// `mcp-typescript/src`) so they don't pollute the report.
			if !reTierPrefix.MatchString(se.Name()) {
				continue
			}
			out = append(out, filepath.Join(base, e.Name(), se.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}

// reTierPrefix extracts the leading two digits from a directory name
// (e.g. "01-mcp-server-basic" -> "01").
var reTierPrefix = regexp.MustCompile(`^(\d{2})[-_]`)

func tierOf(dir string) string {
	base := filepath.Base(dir)
	m := reTierPrefix.FindStringSubmatch(base)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

func analyzeExample(dir string, budgets Budgets, opts runOptions) (ExampleReport, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return ExampleReport{}, err
	}
	if !info.IsDir() {
		return ExampleReport{}, fmt.Errorf("%s is not a directory", dir)
	}

	agg := CountResult{}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip vendored / build / VCS directories.
			name := d.Name()
			if name == "node_modules" || name == "vendor" || name == ".git" ||
				name == "dist" || name == "build" || name == "__pycache__" ||
				name == ".venv" || name == "venv" {
				return filepath.SkipDir
			}
			return nil
		}
		lang, ok := languageFor(path)
		if !ok {
			return nil
		}
		b, err := os.ReadFile(path) //nolint:gosec // G304: reading a source file under examples/
		if err != nil {
			return err
		}
		agg.Add(countSource(string(b), lang))
		return nil
	})
	if err != nil {
		return ExampleReport{}, err
	}

	sdk := detectSDK(dir)

	banner := BannerData{AuthLines: agg.AuthLines, TotalLines: agg.TotalLines, SDKVersion: sdk}

	tier := tierOf(dir)
	budget := budgets.Tiers[tier]
	report := ExampleReport{
		Path:       dir,
		Tier:       tier,
		AuthLines:  agg.AuthLines,
		TotalLines: agg.TotalLines,
		SDKVersion: sdk,
		Budget:     budget,
		OverBudget: budget > 0 && agg.AuthLines > budget,
	}

	readmePath := filepath.Join(dir, "README.md")
	readmeBytes, readErr := os.ReadFile(readmePath) //nolint:gosec // G304: reading the per-example README
	readmeMissing := os.IsNotExist(readErr)
	if readErr != nil && !readmeMissing {
		return ExampleReport{}, readErr
	}

	if !readmeMissing {
		updated, changed := applyBanner(string(readmeBytes), banner)
		report.BannerStale = changed
		if opts.Regenerate && changed {
			if err := os.WriteFile(readmePath, []byte(updated), 0o644); err != nil { //nolint:gosec // G306: README is world-readable by design
				return ExampleReport{}, err
			}
			// After writing, banner is fresh.
			report.BannerStale = false
		}
	}

	return report, nil
}

// detectSDK inspects an example directory for a known SDK pin and
// returns a string suitable for the banner. Returns "(none)" if no
// recognized SDK declaration is found.
func detectSDK(dir string) string {
	// Go module — look for `github.com/authplane/go-sdk v...` in go.mod.
	if v := detectGoSDK(filepath.Join(dir, "go.mod")); v != "" {
		return "go-sdk " + v
	}
	// Node — look for `@authplane/sdk` in package.json.
	if v := detectNodeSDK(filepath.Join(dir, "package.json")); v != "" {
		return "ts-sdk " + v
	}
	// Python — look for `authplane-sdk` in pyproject.toml.
	if v := detectPySDK(filepath.Join(dir, "pyproject.toml")); v != "" {
		return "python-sdk " + v
	}
	return "(none)"
}

// Tolerates a sub-module suffix (e.g. `github.com/authplane/go-sdk/mcp v0.1.0`)
// so subpath imports like `go-sdk/mcp` and `go-sdk/core` also surface the
// SDK version in the banner. The version capture restricts to characters
// that can appear in a Go module version (`v`, digits, dots, hyphens,
// underscores, plus, lowercase letters for pseudo-version stamps) so a
// stray trailing backtick or punctuation from surrounding go.mod comments
// doesn't get captured.
var reGoSDKPin = regexp.MustCompile(`github\.com/authplane/go-sdk(?:/[^\s` + "`" + `]+)?\s+(v[0-9][\w.+-]*)`)

func detectGoSDK(path string) string {
	b, err := os.ReadFile(path) //nolint:gosec // G304: reading the example's go.mod for SDK pin detection
	if err != nil {
		return ""
	}
	m := reGoSDKPin.FindStringSubmatch(string(b))
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

var reNodeSDKPin = regexp.MustCompile(`"@authplane/sdk"\s*:\s*"([^"]+)"`)

func detectNodeSDK(path string) string {
	b, err := os.ReadFile(path) //nolint:gosec // G304: reading the example's package.json for SDK pin detection
	if err != nil {
		return ""
	}
	m := reNodeSDKPin.FindStringSubmatch(string(b))
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

// detectPySDK handles common pyproject shapes:
//
//	authplane-sdk = "1.2.3"
//	"authplane-sdk>=1.2.3"
//	authplane-sdk==1.2.3
var rePySDKPin = regexp.MustCompile(`authplane[-_]sdk[^"'=<>!~\s]*\s*[=:"]+\s*"?([^"',\s]+)`)

func detectPySDK(path string) string {
	b, err := os.ReadFile(path) //nolint:gosec // G304: reading the example's pyproject.toml for SDK pin detection
	if err != nil {
		return ""
	}
	m := rePySDKPin.FindStringSubmatch(string(b))
	if len(m) >= 2 {
		return strings.Trim(m[1], `"'`)
	}
	return ""
}

// loadBudgets reads the YAML budgets file. If path is empty, it falls
// back to budgets.yaml next to the loccount source (resolved via the
// running binary's directory or the working directory).
func loadBudgets(path string) (Budgets, error) {
	if path == "" {
		// Try a few sensible defaults so the tool works from repo root,
		// from tools/loccount/, or when invoked from CI.
		candidates := []string{
			"tools/loccount/budgets.yaml",
			"budgets.yaml",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				path = c
				break
			}
		}
	}
	if path == "" {
		// No file found — return empty budgets so --budget is a no-op.
		return Budgets{Tiers: map[string]int{}}, nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: reading the budgets YAML
	if err != nil {
		return Budgets{}, err
	}
	var out Budgets
	if err := yaml.Unmarshal(b, &out); err != nil {
		return Budgets{}, err
	}
	if out.Tiers == nil {
		out.Tiers = map[string]int{}
	}
	return out, nil
}

func printHuman(reports []ExampleReport) {
	if len(reports) == 0 {
		fmt.Println("loccount: no examples found")
		return
	}
	for _, r := range reports {
		marker := " "
		if r.OverBudget {
			marker = "!"
		} else if r.BannerStale {
			marker = "*"
		}
		budget := "-"
		if r.Budget > 0 {
			budget = fmt.Sprintf("%d", r.Budget)
		}
		fmt.Printf("%s %-50s tier=%s auth=%-4d total=%-5d budget=%-4s sdk=%s\n",
			marker, r.Path, r.Tier, r.AuthLines, r.TotalLines, budget, r.SDKVersion)
	}
	fmt.Println()
	fmt.Println("  legend: '*' banner stale, '!' over budget")
}
