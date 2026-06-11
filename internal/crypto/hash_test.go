package crypto

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestHashSHA256(t *testing.T) {
	hash := HashSHA256("hello")
	// known SHA-256 of "hello"
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if hash != want {
		t.Errorf("HashSHA256(hello) = %q, want %q", hash, want)
	}
}

func TestHashSHA256Deterministic(t *testing.T) {
	h1 := HashSHA256("test-value")
	h2 := HashSHA256("test-value")
	if h1 != h2 {
		t.Error("same input should produce same hash")
	}
}

func TestCompareHashValid(t *testing.T) {
	plain := "my-secret-code"
	hash := HashSHA256(plain)
	if !CompareHash(hash, plain) {
		t.Error("CompareHash should return true for matching hash")
	}
}

func TestCompareHashInvalid(t *testing.T) {
	hash := HashSHA256("correct")
	if CompareHash(hash, "wrong") {
		t.Error("CompareHash should return false for non-matching hash")
	}
}

func TestCompareHashEmpty(t *testing.T) {
	hash := HashSHA256("")
	if !CompareHash(hash, "") {
		t.Error("CompareHash should handle empty strings")
	}
	if CompareHash(hash, "notempty") {
		t.Error("CompareHash should not match empty hash against non-empty")
	}
}

// Matrix: 14.16 — upgraded from ⚠️: hash comparison uses constant-time compare
// This test statically verifies that CompareHash uses crypto/subtle.ConstantTimeCompare
// and that VerifyS256 in pkce.go does the same, preventing timing side-channel attacks.
func TestConstantTimeCompare_UsedInSource(t *testing.T) {
	files := []string{"hash.go", "pkce.go"}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, file, nil, parser.AllErrors)
			if err != nil {
				t.Fatalf("parse %s: %v", file, err)
			}

			found := false
			ast.Inspect(f, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name == "ConstantTimeCompare" {
					ident, ok := sel.X.(*ast.Ident)
					if ok && ident.Name == "subtle" {
						found = true
					}
				}
				return true
			})

			if !found {
				t.Errorf("%s must use subtle.ConstantTimeCompare for timing-safe comparison", file)
			}
		})
	}
}

// Also verify the imports include crypto/subtle in both files.
func TestConstantTimeCompare_SubtleImported(t *testing.T) {
	files := []string{"hash.go", "pkce.go"}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, file, nil, parser.AllErrors)
			if err != nil {
				t.Fatalf("parse %s: %v", file, err)
			}

			found := false
			for _, imp := range f.Imports {
				if strings.Contains(imp.Path.Value, "crypto/subtle") {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s must import crypto/subtle for constant-time comparison", file)
			}
		})
	}
}
