// Package main implements loccount: a small CLI that counts auth-specific
// lines of code inside marked regions in example projects and renders a
// summary banner in each example's README.md.
//
// This file contains the pure counting logic so it can be unit-tested
// independently from filesystem walking and CLI plumbing.
package main

import (
	"bufio"
	"path/filepath"
	"regexp"
	"strings"
)

// LanguageSpec describes how to recognize comments and markers for a
// particular source language.
type LanguageSpec struct {
	// Name is a short identifier (e.g. "go", "python").
	Name string
	// CommentPrefix is the single-line comment prefix that also introduces
	// our begin/end markers (e.g. "//" for Go, "#" for Python).
	CommentPrefix string
}

var (
	specGo     = LanguageSpec{Name: "go", CommentPrefix: "//"}
	specTS     = LanguageSpec{Name: "ts", CommentPrefix: "//"}
	specJS     = LanguageSpec{Name: "js", CommentPrefix: "//"}
	specPython = LanguageSpec{Name: "python", CommentPrefix: "#"}
)

// languageFor returns the LanguageSpec for a given file path based on its
// extension, and whether the extension is one we count at all.
func languageFor(path string) (LanguageSpec, bool) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return specGo, true
	case ".ts", ".tsx":
		return specTS, true
	case ".js", ".jsx", ".mjs", ".cjs":
		return specJS, true
	case ".py":
		return specPython, true
	}
	return LanguageSpec{}, false
}

// beginMarker / endMarker return the exact tokens we look for in each language.
// Markers always live inside a comment so they don't otherwise affect parsing.
func (l LanguageSpec) beginMarker() string { return l.CommentPrefix + " authplane:begin" }
func (l LanguageSpec) endMarker() string   { return l.CommentPrefix + " authplane:end" }

// goImportLine matches Go single-line import statements.
// Multi-line `import ( ... )` blocks are tracked via state, not regex.
var (
	reGoImport     = regexp.MustCompile(`^import\s+`)
	rePyImport     = regexp.MustCompile(`^(import\s+|from\s+\S+\s+import\s+)`)
	reTSJSImport   = regexp.MustCompile(`^import\s+`)
	reGoImportOpen = regexp.MustCompile(`^import\s*\(`)
)

// CountResult is the outcome of counting a single file or aggregating
// multiple files. Lines counts only the auth-specific (between markers)
// content; TotalLines counts non-blank, non-comment lines across the
// whole file regardless of markers.
type CountResult struct {
	AuthLines  int
	TotalLines int
}

// Add merges another result into this one.
func (c *CountResult) Add(o CountResult) {
	c.AuthLines += o.AuthLines
	c.TotalLines += o.TotalLines
}

// countSource analyzes a single source file's contents and returns both
// the auth-marker line count and the total non-blank non-comment count.
//
// The auth count excludes:
//   - blank lines (after trim)
//   - comment lines (lines starting with the language's comment prefix)
//   - import statements (single-line and Go-style `import (...)` blocks)
//
// The total count is computed across the entire file (markers ignored)
// using the same blank/comment exclusion as the auth count, but it does
// NOT exclude imports — "total example size" intentionally includes them.
func countSource(content string, lang LanguageSpec) CountResult {
	res := CountResult{}
	scanner := bufio.NewScanner(strings.NewReader(content))
	// Lines can occasionally be long (minified JS or generated code);
	// bump the buffer to 1MiB.
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	inMarker := false
	inGoImportBlock := false

	for scanner.Scan() {
		raw := scanner.Text()
		trim := strings.TrimSpace(raw)

		// Marker transitions: a marker line itself never counts.
		if strings.HasPrefix(trim, lang.beginMarker()) {
			inMarker = true
			continue
		}
		if strings.HasPrefix(trim, lang.endMarker()) {
			inMarker = false
			continue
		}

		// Total-lines accounting (whole-file, blank/comment excluded).
		if trim != "" && !strings.HasPrefix(trim, lang.CommentPrefix) {
			res.TotalLines++
		}

		if !inMarker {
			continue
		}

		// Auth-lines accounting (only inside markers).
		if trim == "" {
			continue
		}
		if strings.HasPrefix(trim, lang.CommentPrefix) {
			continue
		}

		// Import handling — language-specific.
		switch lang.Name {
		case "go":
			if inGoImportBlock {
				if trim == ")" {
					inGoImportBlock = false
				}
				continue
			}
			if reGoImportOpen.MatchString(trim) {
				// `import (` opens a block that may or may not close on
				// the same line. Detect single-line `import ( ... )`.
				if strings.Contains(trim, ")") {
					// e.g. `import ( "fmt" )` — treat as import, no block.
					continue
				}
				inGoImportBlock = true
				continue
			}
			if reGoImport.MatchString(trim) {
				continue
			}
		case "python":
			if rePyImport.MatchString(trim) {
				continue
			}
		case "ts", "js":
			if reTSJSImport.MatchString(trim) {
				continue
			}
		}

		res.AuthLines++
	}

	return res
}
