// docslinks walks every Markdown file in the repo and verifies that
// inline links of the form `[text](path)` or `[text](path#fragment)`
// resolve: the target file exists, and any `#fragment` matches either an
// explicit `<a id="fragment"></a>` element or a heading whose GitHub
// slug matches the fragment.
//
// The audit found that earlier reference pages used `<!-- anchor: x -->`
// HTML comments as anchor targets — those are invisible to GitHub's
// Markdown renderer and silently fail to scroll. docsgen now emits real
// `<a id>` elements (see tools/docsgen/internal/mdwriter), and this
// checker guards against regression: any new `[label](#bad-slug)` link
// or any rename that breaks an existing one will fail the build.
//
// Scope:
//   - Files: every Markdown root maintained in this repo — enumerated
//     once, in discoverFiles — plus every **/*.md under docs/ and
//     examples/. A root left off that list goes unchecked; that is how
//     SECURITY.md came to carry three dead links.
//   - Inline Markdown links only (`[text](href)`). Reference-style and
//     auto-links are out of scope — the docs don't use them.
//   - Local relative paths. URLs (http/https/mailto/etc) are skipped.
//   - File:line refs (e.g. `internal/foo.go:42`) are treated as plain
//     file paths — fragment must look like an anchor slug, not a line
//     number.
//
// Exit codes: 0 = all green; 1 = broken links found; 2 = setup error.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// inlineLinkRE matches `[text](href)` Markdown inline links. We don't
// try to handle balanced parens inside hrefs — none of our docs use
// them, and the linter is cheap to re-run if a future link triggers
// this case.
var inlineLinkRE = regexp.MustCompile(`\[([^\]]*)\]\(([^)]+)\)`)

// inlineCodeRE matches `…` and “…“ inline code spans. Anything inside
// is treated as literal code, not Markdown — Go signatures like
// `func must[T any](v T, …)` would otherwise look like a [link](v) to
// the inline-link regex.
var inlineCodeRE = regexp.MustCompile("``[^`]*``|`[^`]*`")

// explicitAnchorRE matches `<a id="slug"></a>` (single or double quotes,
// optional whitespace inside the tag). Docsgen always emits the canonical
// double-quoted empty-content form; we accept variations to keep the
// checker friendly to hand-written docs.
var explicitAnchorRE = regexp.MustCompile(`<a[^>]*\sid\s*=\s*"([^"]+)"[^>]*>\s*</a>`)
var explicitAnchorSingleRE = regexp.MustCompile(`<a[^>]*\sid\s*=\s*'([^']+)'[^>]*>\s*</a>`)

// headingRE matches an ATX heading. Setext (===/---) headings are
// allowed by Markdown but neither generator nor any current doc uses
// them.
var headingRE = regexp.MustCompile(`^#{1,6}\s+(.+?)\s*$`)

// gitHubSlug mirrors GitHub's Markdown anchor algorithm for headings:
// lowercase, drop characters outside [a-z0-9 -_], replace spaces with
// dashes. We deliberately do NOT collapse runs of dashes — GitHub keeps
// every dash, so a heading like `Standards & Specifications` slugs to
// `standards--specifications` (two dashes), not `standards-specifications`.
// (We don't model duplicate-suffixing like `-1` — collisions are rare
// in this repo and would surface as a false negative the operator can
// disambiguate manually.)
var gitHubSlugStrip = regexp.MustCompile(`[^a-z0-9\- _]+`)

func gitHubSlug(text string) string {
	s := strings.ToLower(strings.TrimSpace(text))
	// Strip backticks first since they're decorative in headings like
	// `## ` + "`config`" + `` — github keeps the inner word.
	s = strings.ReplaceAll(s, "`", "")
	s = gitHubSlugStrip.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, " ", "-")
	return s
}

// fileAnchors returns the set of resolvable fragment slugs in a file:
// every explicit `<a id="...">` plus every heading's github slug.
func fileAnchors(path string) (map[string]struct{}, error) {
	f, err := os.Open(path) // #nosec G304 -- docslinks' job is to read doc files by path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	anchors := map[string]struct{}{}
	scanner := bufio.NewScanner(f)
	// Some generated tables are wider than the default 64k line limit.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	inFence := false
	fenceRE := regexp.MustCompile("^(```|~~~)")
	for scanner.Scan() {
		line := scanner.Text()
		if fenceRE.MatchString(line) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		// Explicit anchors can appear on any line (typically right
		// after a heading in our generated docs).
		for _, m := range explicitAnchorRE.FindAllStringSubmatch(line, -1) {
			anchors[m[1]] = struct{}{}
		}
		for _, m := range explicitAnchorSingleRE.FindAllStringSubmatch(line, -1) {
			anchors[m[1]] = struct{}{}
		}
		// Heading slugs.
		if m := headingRE.FindStringSubmatch(line); m != nil {
			anchors[gitHubSlug(m[1])] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return anchors, nil
}

// brokenLink is a single failure for the report.
type brokenLink struct {
	SourceFile string
	SourceLine int
	Href       string
	Reason     string
}

func checkFile(repoRoot, path string, cache map[string]map[string]struct{}, cacheErr map[string]error) ([]brokenLink, error) {
	f, err := os.Open(path) // #nosec G304 -- docslinks' job is to read doc files by path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var out []brokenLink
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := 0
	inFence := false
	fenceRE := regexp.MustCompile("^(```|~~~)")
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if fenceRE.MatchString(line) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		// Replace inline code spans with same-length blanks so the
		// inline-link regex doesn't fire inside `func f[T any](v T)`.
		// Preserving length keeps reported column offsets meaningful
		// for future error messages (line:col).
		scrub := inlineCodeRE.ReplaceAllStringFunc(line, func(s string) string {
			return strings.Repeat(" ", len(s))
		})
		for _, m := range inlineLinkRE.FindAllStringSubmatchIndex(scrub, -1) {
			href := scrub[m[4]:m[5]]
			href = strings.TrimSpace(href)
			// Strip optional title: `[t](href "title")`.
			if idx := strings.Index(href, " "); idx >= 0 {
				href = href[:idx]
			}
			if href == "" {
				continue
			}
			// Skip external + protocol-y schemes.
			lower := strings.ToLower(href)
			if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") ||
				strings.HasPrefix(lower, "mailto:") || strings.HasPrefix(lower, "tel:") ||
				strings.HasPrefix(lower, "data:") {
				continue
			}
			// Same-file anchor.
			var targetPath, fragment string
			if strings.HasPrefix(href, "#") {
				targetPath = path
				fragment = strings.TrimPrefix(href, "#")
			} else if idx := strings.Index(href, "#"); idx >= 0 {
				targetPath = href[:idx]
				fragment = href[idx+1:]
			} else {
				targetPath = href
			}
			// GitHub-style file:LINE references aren't fragments —
			// `internal/foo.go:42` resolves to a file viewer URL.
			// Strip the `:LINE` suffix before checking existence.
			if idx := strings.LastIndex(targetPath, ":"); idx >= 0 {
				suffix := targetPath[idx+1:]
				if isDigitOnly(suffix) {
					targetPath = targetPath[:idx]
				}
			}

			// Resolve targetPath relative to the source file's dir.
			if !filepath.IsAbs(targetPath) {
				targetPath = filepath.Clean(filepath.Join(filepath.Dir(path), targetPath))
			}

			// Existence check. Directories also resolve (Markdown links
			// to directories work in GitHub).
			st, statErr := os.Stat(targetPath)
			if statErr != nil {
				out = append(out, brokenLink{
					SourceFile: relTo(repoRoot, path),
					SourceLine: lineNum,
					Href:       href,
					Reason:     "target path does not exist: " + relTo(repoRoot, targetPath),
				})
				continue
			}
			if fragment == "" {
				continue
			}
			// A fragment on a directory link is meaningless — flag it.
			if st.IsDir() {
				out = append(out, brokenLink{
					SourceFile: relTo(repoRoot, path),
					SourceLine: lineNum,
					Href:       href,
					Reason:     "fragment on a directory target",
				})
				continue
			}
			// File:line refs aren't Markdown anchors; only emit if the
			// fragment is shaped like an anchor slug (no digits-only).
			if isDigitOnly(fragment) {
				continue
			}
			// We only resolve fragments inside Markdown / plain-text
			// files we know how to scan.
			if !looksLikeMarkdown(targetPath) {
				continue
			}
			// Cached anchor set.
			anchors, ok := cache[targetPath]
			if !ok {
				if _, seen := cacheErr[targetPath]; seen {
					continue // already reported on first encounter
				}
				anchors, err = fileAnchors(targetPath)
				if err != nil {
					cacheErr[targetPath] = err
					out = append(out, brokenLink{
						SourceFile: relTo(repoRoot, path),
						SourceLine: lineNum,
						Href:       href,
						Reason:     "unable to read target for anchor check: " + err.Error(),
					})
					continue
				}
				cache[targetPath] = anchors
			}
			if _, found := anchors[fragment]; !found {
				out = append(out, brokenLink{
					SourceFile: relTo(repoRoot, path),
					SourceLine: lineNum,
					Href:       href,
					Reason:     "fragment #" + fragment + " not found in " + relTo(repoRoot, targetPath),
				})
			}
		}
	}
	return out, scanner.Err()
}

func relTo(root, p string) string {
	if r, err := filepath.Rel(root, p); err == nil {
		return r
	}
	return p
}

func isDigitOnly(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func looksLikeMarkdown(path string) bool {
	low := strings.ToLower(path)
	if strings.HasSuffix(low, ".md") {
		return true
	}
	// AGENTS, CONTRIBUTING, README without extension already get .md;
	// llms.txt is plain text but our parser handles it (no anchors).
	if strings.HasSuffix(low, "llms.txt") {
		return true
	}
	return false
}

func discoverFiles(repoRoot string) ([]string, error) {
	var out []string
	roots := []string{
		"README.md", "AGENTS.md", "CONTRIBUTING.md", "SECURITY.md",
		"CODE_OF_CONDUCT.md", "CHANGELOG.md",
		"PROJECT_LAYOUT_DATA_ENCRYPTION.md", "llms.txt",
		"docs", "examples",
	}
	for _, r := range roots {
		full := filepath.Join(repoRoot, r)
		st, err := os.Stat(full)
		if err != nil {
			// Tolerate missing optional roots (llms.txt, AGENTS.md).
			continue
		}
		if !st.IsDir() {
			out = append(out, full)
			continue
		}
		err = filepath.Walk(full, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				// Skip generated node_modules / dist / venv noise.
				name := info.Name()
				if name == "node_modules" || name == "dist" || name == ".venv" || name == "__pycache__" {
					return filepath.SkipDir
				}
				return nil
			}
			low := strings.ToLower(info.Name())
			if strings.HasSuffix(low, ".md") {
				out = append(out, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

func main() {
	var quiet bool
	flag.BoolVar(&quiet, "quiet", false, "only print broken links + summary")
	flag.Parse()

	repoRoot, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "docslinks: getcwd:", err)
		os.Exit(2)
	}

	files, err := discoverFiles(repoRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "docslinks: walk:", err)
		os.Exit(2)
	}

	if !quiet {
		fmt.Printf("docslinks: checking %d files\n", len(files))
	}

	cache := map[string]map[string]struct{}{}
	cacheErr := map[string]error{}
	var broken []brokenLink
	for _, f := range files {
		issues, err := checkFile(repoRoot, f, cache, cacheErr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "docslinks: %s: %v\n", relTo(repoRoot, f), err)
			os.Exit(2)
		}
		broken = append(broken, issues...)
	}

	if len(broken) == 0 {
		if !quiet {
			fmt.Println("docslinks: all links resolve")
		}
		return
	}

	fmt.Fprintf(os.Stderr, "docslinks: %d broken link(s):\n", len(broken))
	for _, b := range broken {
		fmt.Fprintf(os.Stderr, "  %s:%d  %s  — %s\n", b.SourceFile, b.SourceLine, b.Href, b.Reason)
	}
	os.Exit(1)
}
