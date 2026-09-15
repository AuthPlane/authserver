// Package ssrf provides SSRF-safe HTTP transport that blocks connections
// to private/reserved IP addresses. Used by OIDC and CIMD adapters.
package ssrf

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// privateNetworks defines the CIDR ranges considered non-routable for the
// purposes of SSRF protection: anything that is not globally-unicast public
// internet space. The list is derived from the IANA special-use registries
// (cited per entry) rather than mirrored from stdlib helpers — the LOW
// finding in the 2026-05-18 audit hid in exactly the gap between
// net.IP.IsPrivate/IsLinkLocal* and the actual IANA list.
var privateNetworks = []net.IPNet{
	// IPv4 — pre-existing.
	parseCIDR("127.0.0.0/8"),    // RFC 1122 loopback
	parseCIDR("10.0.0.0/8"),     // RFC 1918 private
	parseCIDR("172.16.0.0/12"),  // RFC 1918 private
	parseCIDR("192.168.0.0/16"), // RFC 1918 private
	parseCIDR("169.254.0.0/16"), // RFC 3927 link-local
	parseCIDR("0.0.0.0/8"),      // RFC 1122 "this" network

	// IPv4 — added 2026-05-18 audit follow-up.
	parseCIDR("100.64.0.0/10"),   // RFC 6598 CGNAT — carrier-grade NAT; not internet-routable
	parseCIDR("192.0.0.0/24"),    // RFC 6890 IETF protocol assignments
	parseCIDR("192.0.2.0/24"),    // RFC 5737 TEST-NET-1
	parseCIDR("198.18.0.0/15"),   // RFC 2544 benchmark
	parseCIDR("198.51.100.0/24"), // RFC 5737 TEST-NET-2
	parseCIDR("203.0.113.0/24"),  // RFC 5737 TEST-NET-3
	parseCIDR("224.0.0.0/4"),     // RFC 5771 multicast
	parseCIDR("240.0.0.0/4"),     // RFC 1112 reserved (Class E); also covers 255.255.255.255

	// IPv6 — pre-existing.
	parseCIDR("::1/128"),   // RFC 4291 loopback
	parseCIDR("fc00::/7"),  // RFC 4193 unique local addresses
	parseCIDR("fe80::/10"), // RFC 4291 link-local

	// IPv6 — added 2026-05-18 audit follow-up.
	parseCIDR("::/128"),        // RFC 4291 unspecified
	parseCIDR("2001:db8::/32"), // RFC 3849 documentation
	parseCIDR("ff00::/8"),      // RFC 4291 multicast (all scopes)
}

func parseCIDR(s string) net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("invalid CIDR: " + s)
	}
	return *n
}

// IsPrivateIP returns true if the given IP is in a private or reserved range.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range privateNetworks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ipResolver is the DNS seam. Production uses net.DefaultResolver; tests
// substitute a fixed answer so a dial-time assertion can name an address.
type ipResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type safeConfig struct {
	allowPrivate bool
	resolver     ipResolver
}

// Option configures a safe transport.
type Option func(*safeConfig)

// AllowPrivate permits connections to the private and reserved ranges this
// package otherwise refuses — loopback, RFC 1918 space, link-local including
// the cloud metadata endpoint, and the rest of privateNetworks. It turns the
// address filter off; it is for local development, and the caller is expected
// to have made that choice explicit and visible to the operator.
func AllowPrivate() Option {
	return func(c *safeConfig) { c.allowPrivate = true }
}

// withResolver substitutes the DNS resolver. Unexported: tests in this package
// use it to assert on a named address without depending on real DNS. It reaches
// only the filtering path — with the filter off nothing is resolved here.
func withResolver(r ipResolver) Option {
	return func(c *safeConfig) { c.resolver = r }
}

// NewSafeTransport returns an http.Transport that blocks connections to
// private/reserved IP addresses. Used for outbound HTTP requests
// (OIDC discovery, CIMD fetch, etc.) to prevent SSRF attacks.
//
// Proxy is deliberately unset, unlike http.DefaultTransport, so no transport
// from here honors HTTP_PROXY/HTTPS_PROXY. It is not an omission to correct:
// with a proxy configured, DialContext is handed the proxy's address and never
// the target's, so the filter below would clear the proxy and let the request
// through to whatever the target was. ForceAttemptHTTP2 is unset for the same
// reason it is unset on any transport with a custom DialContext — HTTP/2 is not
// negotiated on these connections.
func NewSafeTransport(opts ...Option) *http.Transport {
	cfg := &safeConfig{resolver: net.DefaultResolver}
	for _, opt := range opts {
		opt(cfg)
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Filter off: there is no address to inspect, so the name goes to
			// the dialer untouched and it picks among every address the name
			// resolves to. Resolving here would pin the dial to one of them,
			// which fails whenever the listener is on another — a hostname
			// resolving to both ::1 and 127.0.0.1 against an IPv4-only server
			// being the ordinary local-development case.
			if cfg.allowPrivate {
				return dialer.DialContext(ctx, network, addr)
			}

			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("ssrf: invalid address %q: %w", addr, err)
			}

			// Resolve hostname to IPs.
			ips, err := cfg.resolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("ssrf: DNS resolution failed for %q: %w", host, err)
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("ssrf: no addresses resolved for %q", host)
			}

			// Check all resolved IPs before connecting.
			for _, ipAddr := range ips {
				if IsPrivateIP(ipAddr.IP) {
					return nil, fmt.Errorf("ssrf: blocked connection to private IP %s (resolved from %s)", ipAddr.IP, host)
				}
			}

			// Connect to the first resolved address.
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
	}
}
