// Package srcref formats AST positions as repo-relative "file:line"
// references suitable for embedding in generated reference docs.
//
// Generators usually want to point a reader at the exact source line
// that defines a flag, route, or config field. srcref handles the
// fiddly bits: resolving go/token.Pos against a FileSet, trimming an
// absolute path to a repo-relative one, and degrading gracefully when
// the position is invalid.
package srcref

import (
	"go/token"
	"path/filepath"
	"strings"
)

// SrcRef formats positions against a shared FileSet.
type SrcRef struct {
	fset *token.FileSet
}

// New returns a SrcRef bound to fset. The FileSet must outlive the
// SrcRef; it typically lives for the duration of a single docsgen run.
func New(fset *token.FileSet) *SrcRef {
	return &SrcRef{fset: fset}
}

// Format renders pos as "path/to/file.go:LINE". If root is non-empty
// and the resolved filename lives underneath root, the result is
// relative to root; otherwise the absolute filename is used.
//
// Returns "" if the position is invalid or the FileSet is nil.
func (s *SrcRef) Format(pos token.Pos, root string) string {
	if s == nil || s.fset == nil || !pos.IsValid() {
		return ""
	}
	p := s.fset.Position(pos)
	if p.Filename == "" {
		return ""
	}
	name := p.Filename
	if root != "" {
		if rel, err := filepath.Rel(root, name); err == nil && !strings.HasPrefix(rel, "..") {
			name = rel
		}
	}
	// Normalise to forward slashes so output is identical on Windows.
	name = filepath.ToSlash(name)
	return name + ":" + itoa(p.Line)
}

// itoa is a tiny inlining of strconv.Itoa to keep the package's import
// surface minimal; line numbers are always non-negative.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
