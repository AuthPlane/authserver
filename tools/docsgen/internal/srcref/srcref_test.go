package srcref

import (
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// addFakeFile registers a virtual file in fset with size bytes and sets
// the line table so that pos = base + offset corresponds to a real line.
func addFakeFile(fset *token.FileSet, name string, lines []int, size int) *token.File {
	f := fset.AddFile(name, fset.Base(), size)
	f.SetLines(lines)
	return f
}

func TestFormat_NilOrInvalid(t *testing.T) {
	var s *SrcRef
	if got := s.Format(token.NoPos, ""); got != "" {
		t.Errorf("nil receiver should return empty, got %q", got)
	}
	s = New(token.NewFileSet())
	if got := s.Format(token.NoPos, ""); got != "" {
		t.Errorf("NoPos should return empty, got %q", got)
	}
}

func TestFormat_AbsolutePath(t *testing.T) {
	fset := token.NewFileSet()
	// Lines start at offsets 0, 10, 20 -> lines 1, 2, 3.
	f := addFakeFile(fset, "/abs/path/internal/config/config.go", []int{0, 10, 20}, 100)
	pos := f.Pos(15) // somewhere on line 2
	s := New(fset)

	got := s.Format(pos, "")
	want := "/abs/path/internal/config/config.go:2"
	if got != want {
		t.Errorf("absolute format: got %q want %q", got, want)
	}
}

func TestFormat_RelativeToRoot(t *testing.T) {
	fset := token.NewFileSet()
	f := addFakeFile(fset, "/repo/internal/config/config.go", []int{0, 10, 20, 30}, 100)
	pos := f.Pos(25) // line 3
	s := New(fset)

	got := s.Format(pos, "/repo")
	want := "internal/config/config.go:3"
	if got != want {
		t.Errorf("relative format: got %q want %q", got, want)
	}
}

func TestFormat_RootMismatchFallsBackToAbsolute(t *testing.T) {
	fset := token.NewFileSet()
	f := addFakeFile(fset, "/elsewhere/foo.go", []int{0}, 20)
	pos := f.Pos(1)
	s := New(fset)

	got := s.Format(pos, "/repo")
	if !strings.HasSuffix(got, "/elsewhere/foo.go:1") {
		t.Errorf("expected absolute fallback, got %q", got)
	}
}

func TestFormat_SlashNormalised(t *testing.T) {
	fset := token.NewFileSet()
	// Use filepath.FromSlash so we exercise the OS-native form on Windows.
	native := filepath.FromSlash("/repo/internal/x/y.go")
	f := addFakeFile(fset, native, []int{0}, 10)
	pos := f.Pos(1)
	s := New(fset)

	got := s.Format(pos, "/repo")
	if strings.ContainsRune(got, '\\') {
		t.Errorf("output should use forward slashes, got %q", got)
	}
}

func TestItoa(t *testing.T) {
	cases := map[int]string{0: "0", 1: "1", 42: "42", 1000: "1000", -7: "-7"}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q want %q", in, got, want)
		}
	}
}
