package main

import (
	"path/filepath"
	"testing"
)

func TestLanguageFor(t *testing.T) {
	cases := []struct {
		path string
		ok   bool
		name string
	}{
		{"foo.go", true, "go"},
		{"foo.GO", true, "go"},
		{"a/b/c.ts", true, "ts"},
		{"a/b/c.tsx", true, "ts"},
		{"x.js", true, "js"},
		{"x.mjs", true, "js"},
		{"x.py", true, "python"},
		{"README.md", false, ""},
		{"go.mod", false, ""},
	}
	for _, c := range cases {
		lang, ok := languageFor(filepath.FromSlash(c.path))
		if ok != c.ok {
			t.Fatalf("languageFor(%q): ok=%v want %v", c.path, ok, c.ok)
		}
		if ok && lang.Name != c.name {
			t.Fatalf("languageFor(%q): name=%q want %q", c.path, lang.Name, c.name)
		}
	}
}

func TestCountSource_GoExcludesImportsAndComments(t *testing.T) {
	src := `package main

import "fmt"

import (
	"os"
	"strings"
)

// authplane:begin
import "errors"
import (
	"context"
	"io"
)
// a real comment that should not count

if err := doThing(); err != nil {
	return err
}
// authplane:end

func unrelated() {}
`
	got := countSource(src, specGo)
	// Auth count: the if statement (3 lines: if/return/}), excluding
	// imports, comments, blank, and markers themselves.
	if got.AuthLines != 3 {
		t.Fatalf("AuthLines=%d want 3 (src=%s)", got.AuthLines, src)
	}
	// Total: every non-blank, non-comment line in the file (markers
	// are comments so they don't count). package, two import singletons,
	// the two `import (` block lines + 2 contents + ) for first block,
	// then the second import singleton, then import ( ... ) for second
	// block, then the if/return/}, then func line.
	if got.TotalLines == 0 {
		t.Fatalf("TotalLines should be > 0")
	}
}

func TestCountSource_PythonExcludesImports(t *testing.T) {
	src := `# authplane:begin
import os
from typing import Optional
from .sdk import Client

client = Client()
client.do_thing()
# trailing comment

# authplane:end
print("outside")
`
	got := countSource(src, specPython)
	if got.AuthLines != 2 {
		t.Fatalf("AuthLines=%d want 2", got.AuthLines)
	}
}

func TestCountSource_TSImports(t *testing.T) {
	src := `// authplane:begin
import { Client } from "@authplane/sdk";
import type { Foo } from "./foo";

const c = new Client();
c.doThing();
// authplane:end
`
	got := countSource(src, specTS)
	if got.AuthLines != 2 {
		t.Fatalf("AuthLines=%d want 2", got.AuthLines)
	}
}

func TestCountSource_MultiRegion(t *testing.T) {
	src := `package main

// authplane:begin
a := 1
b := 2
// authplane:end

func boring() {
	noop()
}

// authplane:begin
c := 3
// authplane:end
`
	got := countSource(src, specGo)
	if got.AuthLines != 3 {
		t.Fatalf("multi-region AuthLines=%d want 3", got.AuthLines)
	}
}

func TestCountSource_NoMarkers(t *testing.T) {
	src := `package main

func main() {
	println("hi")
}
`
	got := countSource(src, specGo)
	if got.AuthLines != 0 {
		t.Fatalf("AuthLines=%d want 0", got.AuthLines)
	}
	if got.TotalLines != 4 {
		t.Fatalf("TotalLines=%d want 4 (package, func sig, body, brace)", got.TotalLines)
	}
}

func TestCountSource_SingleLineGoImportBlock(t *testing.T) {
	// `import ( "fmt" )` on one line — should be skipped, not open a
	// runaway import block.
	src := `// authplane:begin
import ( "fmt" )
doSomething()
// authplane:end
`
	got := countSource(src, specGo)
	if got.AuthLines != 1 {
		t.Fatalf("AuthLines=%d want 1", got.AuthLines)
	}
}

func TestTierOf(t *testing.T) {
	cases := map[string]string{
		"examples/foo/01-mcp-server-basic": "01",
		"examples/foo/02-something":        "02",
		"examples/foo/no-prefix":           "",
		"examples/foo/100-too-long":        "",
		"01-top-level":                     "01",
	}
	for in, want := range cases {
		got := tierOf(in)
		if got != want {
			t.Errorf("tierOf(%q)=%q want %q", in, got, want)
		}
	}
}
