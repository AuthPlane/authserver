package ssrf

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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
		{"224.0.0.1", "RFC 5771 multicast — inside 224.0.0.0/24, also caught by stdlib"},
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

// TestIsPrivateIP_StdlibHelperGaps pins the exact set of addresses that the
// drifted predicate in internal/adapters/idpjwks allowed through before being
// fixed. Each entry names why the stdlib helpers missed it.
//
// Derived by exhaustive comparison of both predicates over all 4,294,967,296
// IPv4 addresses and their v4-mapped forms, plus CIDR boundaries and 20M random
// addresses in IPv6.
func TestIsPrivateIP_StdlibHelperGaps(t *testing.T) {
	gaps := []struct {
		ip     string
		reason string
	}{
		{"100.64.0.1", "RFC 6598 CGNAT lower — no stdlib helper covers CGNAT"},
		{"100.127.255.255", "RFC 6598 CGNAT upper"},
		{"224.0.1.1", "RFC 5771 — IsLinkLocalMulticast covers only 224.0.0.0/24"},
		{"239.255.255.255", "RFC 5771 multicast upper"},
		{"240.0.0.1", "RFC 1112 Class E — no stdlib helper"},
		{"255.255.255.255", "RFC 1112 /4 also covers limited broadcast"},
		{"0.1.2.3", "RFC 1122 — IsUnspecified is exact-match on 0.0.0.0"},
		{"0.255.255.255", "RFC 1122 0.0.0.0/8 upper"},
		{"192.0.0.1", "RFC 6890 IETF protocol assignments"},
		{"192.0.2.1", "RFC 5737 TEST-NET-1"},
		{"198.18.0.1", "RFC 2544 benchmark lower"},
		{"198.19.255.255", "RFC 2544 benchmark upper"},
		{"198.51.100.1", "RFC 5737 TEST-NET-2"},
		{"203.0.113.1", "RFC 5737 TEST-NET-3"},
		{"2001:db8::1", "RFC 3849 IPv6 documentation"},
		{"ff05::1", "RFC 4291 — IsLinkLocalMulticast covers only ff02::/16"},
		{"ff0e::1", "RFC 4291 global-scope multicast"},
		{"::ffff:100.64.0.1", "v4-mapped CGNAT — must normalise through To4()"},
	}
	if len(gaps) != 18 {
		t.Fatalf("gap set has %d entries, want 18", len(gaps))
	}
	for _, c := range gaps {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("parse %q: nil", c.ip)
		}
		if !IsPrivateIP(ip) {
			t.Errorf("regression: IsPrivateIP(%s) = false, want true (%s)", c.ip, c.reason)
		}
	}

	// Controls the drifted predicate already handled — these must stay blocked.
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "::ffff:127.0.0.1"} {
		if !IsPrivateIP(net.ParseIP(s)) {
			t.Errorf("control regression: IsPrivateIP(%s) = false, want true", s)
		}
	}
	// And public space must stay reachable.
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"} {
		if IsPrivateIP(net.ParseIP(s)) {
			t.Errorf("false positive: IsPrivateIP(%s) = true, want false", s)
		}
	}
}

// stubResolver returns fixed answers so a dial-time test can name an address
// without depending on real DNS.
type stubResolver map[string][]net.IPAddr

func (s stubResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if addrs, ok := s[host]; ok {
		return addrs, nil
	}
	return nil, fmt.Errorf("stub resolver: no answer for %q", host)
}

// privateHosts are hostnames resolving into each range the guard refuses. The
// dial-time hostname path is the one a caller's URL-level check cannot cover,
// so it gets per-range coverage here.
var privateHosts = []struct {
	host string
	ip   string
}{
	{"metadata.test", "169.254.169.254"},
	{"internal.test", "10.0.0.5"},
	{"lan.test", "192.168.1.50"},
	{"corp.test", "172.16.0.1"},
	{"cgnat.test", "100.64.0.1"},
	{"ula.test", "fc00::1"},
	{"lladdr.test", "fe80::1"},
	{"loop.test", "127.0.0.1"},
}

// The default transport refuses a hostname resolving into any blocked range.
func TestNewSafeTransport_BlocksHostnamesResolvingToPrivate(t *testing.T) {
	for _, c := range privateHosts {
		t.Run(c.host, func(t *testing.T) {
			res := stubResolver{c.host: {{IP: net.ParseIP(c.ip)}}}
			tr := NewSafeTransport(withResolver(res))
			client := &http.Client{Transport: tr, Timeout: 2 * time.Second}

			req, err := http.NewRequestWithContext(context.Background(),
				http.MethodGet, "http://"+c.host+"/", http.NoBody)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			resp, err := client.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if err == nil {
				t.Fatalf("%s (%s) was not refused", c.host, c.ip)
			}
			if !strings.Contains(err.Error(), "blocked connection to private IP") {
				t.Errorf("wrong rejection reason for %s: %v", c.ip, err)
			}
		})
	}
}

// AllowPrivate relaxes the filter: the dial is attempted rather than refused.
// The addresses go in as literals rather than through the resolver stub — with
// the filter off the transport does not resolve at all, so there is no resolver
// seam on this path. Nothing is listening on them, so the assertion is that
// whatever error comes back is a connection failure and not the guard's refusal.
func TestAllowPrivate_DoesNotRefuseByAddress(t *testing.T) {
	for _, c := range privateHosts {
		t.Run(c.ip, func(t *testing.T) {
			t.Parallel()
			tr := NewSafeTransport(AllowPrivate())
			// Short timeout: nothing listens on these addresses, so the dial is
			// expected to fail. The guard refuses before any network I/O, so
			// whatever comes back after a wait is by definition not its refusal.
			client := &http.Client{Transport: tr, Timeout: 250 * time.Millisecond}

			req, err := http.NewRequestWithContext(context.Background(),
				http.MethodGet, "http://"+net.JoinHostPort(c.ip, "1")+"/", http.NoBody)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			resp, err := client.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if err != nil && strings.Contains(err.Error(), "blocked connection to private IP") {
				t.Errorf("AllowPrivate must not refuse %s by address: %v", c.ip, err)
			}
		})
	}
}

// The positive end-to-end case: with AllowPrivate a real loopback listener is
// reachable, which is what the CIMD test suite and the e2e harness depend on.
func TestAllowPrivate_PermitsLoopbackListener(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Transport: NewSafeTransport(AllowPrivate()), Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("AllowPrivate should permit %s: %v", srv.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// A hostname can resolve to several addresses with a listener on only some of
// them: "localhost" is normally both ::1 and 127.0.0.1, and a local document
// server usually binds IPv4 only. The dialer tries each in turn, so the fetch
// works — but only because the filter-off path hands it the name. Resolving
// there and dialing one of the addresses breaks this, and it is the ordinary
// shape of the local-development fetch the option exists for.
func TestAllowPrivate_PermitsHostnameWithIPv4OnlyListener(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}

	client := &http.Client{Transport: NewSafeTransport(AllowPrivate()), Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodGet, "http://localhost:"+port+"/", http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("AllowPrivate should reach the IPv4-only listener via localhost: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// Without the option, that same listener stays unreachable — the default is
// unchanged.
func TestNewSafeTransport_DefaultStillBlocksLoopbackListener(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Transport: NewSafeTransport(), Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("default transport must still block loopback")
	}
}
