package oidc

import (
	"net"
	"net/http"

	"github.com/authplane/authserver/internal/ssrf"
)

// IsPrivateIP delegates to the shared ssrf package.
// Exported for testing in the oidc_test package.
func IsPrivateIP(ip net.IP) bool {
	return ssrf.IsPrivateIP(ip)
}

// newSSRFSafeTransport delegates to the shared ssrf package.
func newSSRFSafeTransport() *http.Transport {
	return ssrf.NewSafeTransport()
}
