package admin

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"regexp"

	webadmin "github.com/authplane/authserver/web/admin"
)

// inlineScriptRe matches the first inline <script>...</script> block (non-module, non-type).
// Used to extract the anti-flash theme script for CSP hash computation.
var inlineScriptRe = regexp.MustCompile(`<script>([^<]+)</script>`)

// computeInlineScriptCSPHash extracts the inline script from the embedded HTML
// and returns a CSP 'sha256-...' directive. If no inline script is found,
// falls back to 'unsafe-inline' for compatibility.
func computeInlineScriptCSPHash() string {
	match := inlineScriptRe.FindSubmatch(webadmin.DistHTML)
	if match == nil {
		return "'unsafe-inline'"
	}
	h := sha256.Sum256(match[1])
	return "'sha256-" + base64.StdEncoding.EncodeToString(h[:]) + "'"
}

// registerUIRoutes serves the embedded admin SPA.
// These routes are NOT protected by API key middleware — the SPA manages
// its own auth via the /admin/auth/verify endpoint.
func registerUIRoutes(mux *http.ServeMux) {
	// M3 fix: compute SHA-256 hash of the inline anti-flash script at startup
	// instead of using blanket 'unsafe-inline' for script-src.
	scriptHash := computeInlineScriptCSPHash()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' "+scriptHash+"; "+
				"style-src 'self' 'unsafe-inline'; "+
				"connect-src 'self'; "+
				"img-src 'self' data:; "+
				"font-src 'self' data:")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(webadmin.DistHTML)
	})

	// Subtree pattern — matches /admin/ui/ and all sub-paths.
	mux.Handle("GET /admin/ui/", handler)
}
