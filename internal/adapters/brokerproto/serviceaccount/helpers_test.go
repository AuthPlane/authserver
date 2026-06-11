package serviceaccount

import (
	"errors"
	"strings"
	"testing"
)

// Error-path coverage for the internal helpers parseConfigData,
// parseCredential, resolveSAKey, validateExternalURL, and truncate.
// Audit HIGH-5: lift adapter coverage from 72.3% by exercising the error
// branches the httptest-driven Vend tests don't reach. Mirrors the
// oauth adapter's helpers_test.go.

// --- parseConfigData ---

func TestParseConfigData_EmptyBytes(t *testing.T) {
	if _, err := parseConfigData(nil); err == nil {
		t.Fatal("nil bytes: expected error, got nil")
	}
	if _, err := parseConfigData([]byte{}); err == nil {
		t.Fatal("empty bytes: expected error, got nil")
	}
}

func TestParseConfigData_InvalidJSON(t *testing.T) {
	_, err := parseConfigData([]byte(`{"token_url":`))
	if err == nil {
		t.Fatal("malformed JSON: expected error, got nil")
	}
}

func TestParseConfigData_MissingRequiredFields(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"missing token_url", `{"sa_email":"a","sa_key_env":"K"}`, "token_url"},
		{"missing sa_email", `{"token_url":"https://x","sa_key_env":"K"}`, "sa_email"},
		{"missing sa_key_env", `{"token_url":"https://x","sa_email":"a"}`, "sa_key_env"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfigData([]byte(tc.raw))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q missing field name %q", err.Error(), tc.want)
			}
		})
	}
}

func TestParseConfigData_DefaultsAlgorithmRS256(t *testing.T) {
	cfg, err := parseConfigData([]byte(`{"token_url":"https://x","sa_email":"a","sa_key_env":"K"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Algorithm != algorithmRS256 {
		t.Errorf("Algorithm = %q, want %q (default)", cfg.Algorithm, algorithmRS256)
	}
}

func TestParseConfigData_RejectsUnsupportedAlgorithm(t *testing.T) {
	_, err := parseConfigData([]byte(
		`{"token_url":"https://x","sa_email":"a","sa_key_env":"K","algorithm":"HS256"}`))
	if err == nil {
		t.Fatal("algorithm=HS256: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Errorf("error %q should mention unsupported algorithm", err.Error())
	}
}

func TestParseConfigData_DefaultsTTLWhenZero(t *testing.T) {
	cfg, err := parseConfigData([]byte(
		`{"token_url":"https://x","sa_email":"a","sa_key_env":"K"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TokenTTLSeconds != defaultTokenTTLSeconds {
		t.Errorf("TokenTTLSeconds = %d, want %d (default)", cfg.TokenTTLSeconds, defaultTokenTTLSeconds)
	}
}

func TestParseConfigData_RejectsNegativeTTL(t *testing.T) {
	_, err := parseConfigData([]byte(
		`{"token_url":"https://x","sa_email":"a","sa_key_env":"K","token_ttl_seconds":-30}`))
	if err == nil {
		t.Fatal("negative TTL: expected error, got nil")
	}
}

// Audit M5: SA TTL must be bounded at config parse — too-short values
// fail upstream verification on clock skew; too-long values exceed
// typical upstream caps.

func TestParseConfigData_RejectsTTLBelowFloor(t *testing.T) {
	// 29s is below the 30s floor.
	_, err := parseConfigData([]byte(
		`{"token_url":"https://x","sa_email":"a","sa_key_env":"K","token_ttl_seconds":29}`))
	if err == nil {
		t.Fatal("TTL=29 (below 30s floor): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "out of bounds") {
		t.Errorf("error %q should mention bounds", err.Error())
	}
}

func TestParseConfigData_RejectsTTLAboveCeiling(t *testing.T) {
	// 3601s is above the 3600s ceiling.
	_, err := parseConfigData([]byte(
		`{"token_url":"https://x","sa_email":"a","sa_key_env":"K","token_ttl_seconds":3601}`))
	if err == nil {
		t.Fatal("TTL=3601 (above 3600s ceiling): expected error, got nil")
	}
}

func TestParseConfigData_AcceptsTTLAtFloor(t *testing.T) {
	cfg, err := parseConfigData([]byte(
		`{"token_url":"https://x","sa_email":"a","sa_key_env":"K","token_ttl_seconds":30}`))
	if err != nil {
		t.Fatalf("TTL=30 (exact floor): unexpected error: %v", err)
	}
	if cfg.TokenTTLSeconds != 30 {
		t.Errorf("TTL = %d, want 30", cfg.TokenTTLSeconds)
	}
}

func TestParseConfigData_AcceptsTTLAtCeiling(t *testing.T) {
	cfg, err := parseConfigData([]byte(
		`{"token_url":"https://x","sa_email":"a","sa_key_env":"K","token_ttl_seconds":3600}`))
	if err != nil {
		t.Fatalf("TTL=3600 (exact ceiling): unexpected error: %v", err)
	}
	if cfg.TokenTTLSeconds != 3600 {
		t.Errorf("TTL = %d, want 3600", cfg.TokenTTLSeconds)
	}
}

// --- parseCredential ---

func TestParseCredential_EmptyBytes(t *testing.T) {
	if _, err := parseCredential(nil); err == nil {
		t.Fatal("nil bytes: expected error, got nil")
	}
}

func TestParseCredential_InvalidJSON(t *testing.T) {
	if _, err := parseCredential([]byte(`{not-json`)); err == nil {
		t.Fatal("malformed JSON: expected error, got nil")
	}
}

func TestParseCredential_MissingImpersonateSub(t *testing.T) {
	_, err := parseCredential([]byte(`{}`))
	if err == nil {
		t.Fatal("expected error for missing impersonate_sub, got nil")
	}
	if !strings.Contains(err.Error(), "impersonate_sub") {
		t.Errorf("error %q should mention impersonate_sub", err.Error())
	}
}

// --- resolveSAKey (reuses stubSecretResolver from adapter_test.go) ---

func TestResolveSAKey_EmptyEnvName(t *testing.T) {
	a := &Adapter{secretResolver: &stubSecretResolver{pem: "x"}}
	_, err := a.resolveSAKey("")
	if !errors.Is(err, errSAKeyLookup) {
		t.Errorf("expected errSAKeyLookup, got %v", err)
	}
}

func TestResolveSAKey_InvalidEnvNamePattern(t *testing.T) {
	a := &Adapter{secretResolver: &stubSecretResolver{pem: "x"}}
	_, err := a.resolveSAKey("not-valid")
	if !errors.Is(err, errSAKeyLookup) {
		t.Errorf("expected errSAKeyLookup, got %v", err)
	}
}

func TestResolveSAKey_NilResolver(t *testing.T) {
	a := &Adapter{secretResolver: nil}
	_, err := a.resolveSAKey("CONNECTOR_SA_KEY")
	if !errors.Is(err, errSAKeyLookup) {
		t.Errorf("expected errSAKeyLookup, got %v", err)
	}
}

func TestResolveSAKey_ResolverReturnsError(t *testing.T) {
	a := &Adapter{secretResolver: &stubSecretResolver{err: errors.New("secret unavailable")}}
	_, err := a.resolveSAKey("CONNECTOR_SA_KEY")
	if !errors.Is(err, errSAKeyLookup) {
		t.Errorf("expected errSAKeyLookup wrap, got %v", err)
	}
}

func TestResolveSAKey_ResolverReturnsEmpty(t *testing.T) {
	a := &Adapter{secretResolver: &stubSecretResolver{pem: ""}}
	_, err := a.resolveSAKey("CONNECTOR_SA_KEY")
	if !errors.Is(err, errSAKeyLookup) {
		t.Errorf("expected errSAKeyLookup, got %v", err)
	}
}

// --- validateExternalURL (mirrors oauth) ---

func TestValidateExternalURL_RejectsLoopbackByDefault(t *testing.T) {
	if err := validateExternalURL("http://127.0.0.1/token", false); err == nil {
		t.Fatal("loopback IP without allowLoopback: expected error, got nil")
	}
}

func TestValidateExternalURL_AllowsLoopbackWhenOptedIn(t *testing.T) {
	if err := validateExternalURL("http://127.0.0.1/token", true); err != nil {
		t.Errorf("loopback with allowLoopback=true: unexpected error: %v", err)
	}
}

func TestValidateExternalURL_RejectsPrivateIP(t *testing.T) {
	for _, host := range []string{"http://10.0.0.1/", "http://192.168.1.1/", "http://172.16.0.1/"} {
		if err := validateExternalURL(host, false); err == nil {
			t.Errorf("%s: expected SSRF rejection, got nil", host)
		}
	}
}

func TestValidateExternalURL_RejectsLinkLocal(t *testing.T) {
	if err := validateExternalURL("http://169.254.169.254/", false); err == nil {
		t.Fatal("link-local (AWS metadata): expected rejection, got nil")
	}
}

func TestValidateExternalURL_RejectsUnspecified(t *testing.T) {
	if err := validateExternalURL("http://0.0.0.0/", false); err == nil {
		t.Fatal("unspecified address: expected rejection, got nil")
	}
}

// Mirrors oauth adapter — IANA special-use ranges that net.IP.Is* misses.
func TestValidateExternalURL_RejectsSpecialUseRanges(t *testing.T) {
	for _, c := range []struct {
		host string
		spec string
	}{
		{"http://100.64.5.5/", "RFC 6598 CGNAT"},
		{"http://192.0.2.1/", "RFC 5737 TEST-NET-1"},
		{"http://198.18.0.1/", "RFC 2544 benchmark"},
		{"http://198.51.100.1/", "RFC 5737 TEST-NET-2"},
		{"http://203.0.113.1/", "RFC 5737 TEST-NET-3"},
		{"http://224.0.0.1/", "RFC 5771 multicast"},
		{"http://240.0.0.1/", "RFC 1112 reserved"},
		{"http://255.255.255.255/", "RFC 919 limited broadcast"},
		{"http://[::]/", "RFC 4291 IPv6 unspecified"},
		{"http://[2001:db8::1]/", "RFC 3849 IPv6 documentation"},
		{"http://[ff02::1]/", "RFC 4291 IPv6 multicast"},
	} {
		if err := validateExternalURL(c.host, false); err == nil {
			t.Errorf("%s (%s): expected SSRF rejection, got nil", c.host, c.spec)
		}
	}
}

func TestValidateExternalURL_HostnameSkipsIPCheck(t *testing.T) {
	if err := validateExternalURL("https://oauth2.googleapis.com/token", false); err != nil {
		t.Errorf("DNS hostname: unexpected error: %v", err)
	}
}

func TestValidateExternalURL_RejectsMalformed(t *testing.T) {
	if err := validateExternalURL("http://example.com:abc/", false); err == nil {
		t.Fatal("malformed URL: expected error, got nil")
	}
}

// --- truncate ---

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"", 10, ""},
		{"abc", 10, "abc"},
		{"abcdef", 3, "abc..."},
		{"abc", 3, "abc"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := truncate(tc.in, tc.n); got != tc.want {
				t.Errorf("truncate(%q,%d) = %q, want %q", tc.in, tc.n, got, tc.want)
			}
		})
	}
}
