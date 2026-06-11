package ssrf

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.0.0.5", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true}, // AWS metadata
		{"0.0.0.0", true},
		{"fc00::1", true},
		{"fe80::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2001:4860:4860::8888", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("parse %q: nil", c.ip)
		}
		if got := IsPrivateIP(ip); got != c.want {
			t.Errorf("IsPrivateIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

// Verifies that NewSafeTransport refuses a hostname whose DNS resolution
// lands on a private IP — the gap the broker-SSRF audit finding flagged.
// "localhost" reliably resolves to 127.0.0.1 / ::1 on the systems this
// codebase builds on; if a developer's resolver returns something else the
// test still passes (private IPs are detected post-resolution).
func TestNewSafeTransport_BlocksHostnameResolvingToPrivateIP(t *testing.T) {
	tr := NewSafeTransport()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost:1/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected SSRF rejection, got nil")
	}
	if !strings.Contains(err.Error(), "ssrf:") {
		t.Errorf("error = %v, want contains ssrf: prefix", err)
	}
}

// IsPrivateIP_SpecialUseRanges asserts that the predicate blocks ALL of the
// IANA-special-use ranges, not just the "obvious private" ones. Cases are
// drawn from external authoritative references (RFC 6890, RFC 5735, RFC 5737,
// RFC 6598, RFC 4193, RFC 3849, RFC 4291) rather than mirroring whatever the
// implementation currently knows about — that's how the LOW finding hid.
//
// Each entry records the RFC so future readers can defend the choice.
// Pre-fix the loopback/RFC1918/link-local cases pass; everything below those
// is the gap.
func TestIsPrivateIP_SpecialUseRanges(t *testing.T) {
	blocked := []struct {
		ip   string
		spec string
	}{
		// IPv4 — pre-existing coverage (regression pin).
		{"127.0.0.1", "RFC 1122 loopback"},
		{"127.255.255.254", "RFC 1122 loopback /8"},
		{"10.0.0.5", "RFC 1918"},
		{"10.255.255.255", "RFC 1918 /8"},
		{"172.16.0.1", "RFC 1918"},
		{"172.31.255.255", "RFC 1918 /12 upper"},
		{"192.168.1.1", "RFC 1918"},
		{"192.168.255.255", "RFC 1918 /16 upper"},
		{"169.254.1.1", "RFC 3927 link-local"},
		{"169.254.169.254", "EC2/GCE metadata"},
		{"0.0.0.0", "RFC 1122 'this' network"},
		{"0.255.255.255", "RFC 1122 'this' /8 upper"},

		// IPv4 — new coverage. ALL of these were silently allowed pre-fix.
		{"100.64.0.1", "RFC 6598 CGNAT lower"},
		{"100.127.255.255", "RFC 6598 CGNAT upper"},
		{"192.0.0.1", "RFC 6890 IETF protocol assignments"},
		{"192.0.2.1", "RFC 5737 TEST-NET-1"},
		{"198.18.0.1", "RFC 2544 benchmark lower"},
		{"198.19.255.255", "RFC 2544 benchmark upper"},
		{"198.51.100.1", "RFC 5737 TEST-NET-2"},
		{"203.0.113.1", "RFC 5737 TEST-NET-3"},
		{"224.0.0.1", "RFC 5771 multicast lower"},
		{"239.255.255.255", "RFC 5771 multicast upper"},
		{"240.0.0.1", "RFC 1112 reserved (Class E)"},
		{"255.255.255.255", "RFC 919 limited broadcast"},

		// IPv6 — pre-existing.
		{"::1", "RFC 4291 loopback"},
		{"fc00::1", "RFC 4193 ULA lower"},
		{"fdff:ffff:ffff:ffff::1", "RFC 4193 ULA upper"},
		{"fe80::1", "RFC 4291 link-local"},

		// IPv6 — new coverage.
		{"::", "RFC 4291 unspecified"},
		{"2001:db8::1", "RFC 3849 documentation"},
		{"ff02::1", "RFC 4291 multicast"},
		{"ff05::1:3", "RFC 4291 multicast site-local"},
	}
	for _, c := range blocked {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("parse %q (%s): nil", c.ip, c.spec)
		}
		if !IsPrivateIP(ip) {
			t.Errorf("IsPrivateIP(%s) = false, want true (%s)", c.ip, c.spec)
		}
	}

	allowed := []struct {
		ip   string
		note string
	}{
		// Sanity: representative public addresses must NOT be blocked.
		{"8.8.8.8", "Google DNS"},
		{"1.1.1.1", "Cloudflare DNS"},
		{"2001:4860:4860::8888", "Google DNS v6"},
		{"99.255.255.255", "just below CGNAT lower edge"},
		{"100.63.255.255", "just below CGNAT lower edge — exact boundary"},
		{"100.128.0.0", "just above CGNAT upper edge"},
		{"172.15.255.255", "just below RFC 1918 12-bit lower"},
		{"172.32.0.0", "just above RFC 1918 12-bit upper"},
		{"223.255.255.255", "just below 224.0.0.0 multicast lower edge"},
	}
	for _, c := range allowed {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("parse %q (%s): nil", c.ip, c.note)
		}
		if IsPrivateIP(ip) {
			t.Errorf("IsPrivateIP(%s) = true, want false (%s)", c.ip, c.note)
		}
	}
}

// Direct dial against a literal private IP must also be refused — covers
// the case where the URL hostname is already an IP literal and DNS
// resolution returns it unchanged.
func TestNewSafeTransport_BlocksPrivateIPLiteral(t *testing.T) {
	tr := NewSafeTransport()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://10.0.0.1:1/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected SSRF rejection for private IP literal, got nil")
	}
	if !strings.Contains(err.Error(), "ssrf:") {
		t.Errorf("error = %v, want contains ssrf: prefix", err)
	}
}
