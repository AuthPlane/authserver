// Package webadmin provides the embedded admin UI static files.
// The dist/index.html file is built by the frontend toolchain (vite)
// and inlined as a single HTML file via vite-plugin-singlefile.
// When the UI has not been built, a placeholder page is served.
package webadmin

import _ "embed"

//go:embed dist/index.html

// DistHTML contains the embedded admin UI assets.
var DistHTML []byte
