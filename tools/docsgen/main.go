// Package main implements docsgen: a small CLI that generates reference
// documentation (CLI flags, HTTP API, environment variables, configuration)
// for the Authplane authserver by inspecting the source tree.
//
// This binary is intentionally a shell. The per-generator logic ships in
// subsequent tickets; each subcommand currently writes a stub file with the
// canonical "generated-by" header plus a TODO body so that make docs-check
// semantics work end-to-end immediately.
package main

import (
	"fmt"
	"os"

	"github.com/authplane/authserver/tools/docsgen/cmd"
)

func main() {
	root := cmd.NewRoot()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
