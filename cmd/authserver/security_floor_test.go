package main

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Security floors for the toolchain and the dependencies whose advisories a
// release has closed. Each entry is the first version that carries the fix;
// lowering any of them reopens the advisory, so this test fails instead of
// letting a merge or a dependency tidy quietly downgrade.
//
//   - Go 1.27.3: CVE-2026-111943, crypto/x509 chain verification (outbound
//     TLS to OIDC providers, IdP JWKS, Vault and CIMD). Fixed on the 1.26 line
//     in 1.26.10; the server builds on 1.27, so the floor is the 1.27 fix.
//   - go-jose v4.1.6: CVE-2026-116587, CPU exhaustion from a crafted RSA
//     "jwk" in a JWS header (anonymous via the DPoP header).
//   - golang.org/x/net v0.62.0: CVE-2026-78661 (x/net/html; not linked into
//     the binary, but flagged by the image scan).
var securityFloors = map[string]string{
	"go":                            "1.27.3",
	"github.com/go-jose/go-jose/v4": "4.1.6",
	"golang.org/x/net":              "0.62.0",
}

func TestSecurityFloors_GoMod(t *testing.T) {
	data, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	goMod := string(data)

	goDirective := regexp.MustCompile(`(?m)^go\s+(\S+)\s*$`).FindStringSubmatch(goMod)
	if goDirective == nil {
		t.Fatal("go.mod has no go directive")
	}
	checkFloor(t, "go directive", goDirective[1], securityFloors["go"])

	for mod, floor := range securityFloors {
		if mod == "go" {
			continue
		}
		re := regexp.MustCompile(`(?m)^\s*(?:require\s+)?` + regexp.QuoteMeta(mod) + `\s+v(\S+)`)
		m := re.FindStringSubmatch(goMod)
		if m == nil {
			t.Errorf("go.mod does not require %s", mod)
			continue
		}
		checkFloor(t, mod, m[1], floor)
	}
}

// Every Go example that depends on the Go SDK must resolve go-jose at or above
// the floor. The SDK's token verifier parses every incoming bearer token with
// go-jose before checking it, so an example on an SDK that pins an older
// go-jose (v0.4.0 pins v4.1.4) is anonymously exposed to the same denial of
// service. The examples are on v0.5.0, which pins v4.1.9.
func TestSecurityFloors_GoExamples(t *testing.T) {
	manifests, err := filepath.Glob("../../examples/go/*/go.mod")
	if err != nil {
		t.Fatal(err)
	}
	nested, err := filepath.Glob("../../examples/go/*/*/go.mod")
	if err != nil {
		t.Fatal(err)
	}
	manifests = append(manifests, nested...)
	if len(manifests) == 0 {
		t.Fatal("found no Go example manifests; the glob is wrong")
	}

	const jose = "github.com/go-jose/go-jose/v4"
	joseRe := regexp.MustCompile(`(?m)^\s*(?:require\s+)?` + regexp.QuoteMeta(jose) + `\s+v(\S+)`)
	checked := 0
	for _, path := range manifests {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(data), "github.com/authplane/go-sdk/") {
			continue
		}
		checked++
		m := joseRe.FindStringSubmatch(string(data))
		if m == nil {
			t.Errorf("%s depends on the Go SDK but does not require %s; add it at v%s or later", path, jose, securityFloors[jose])
			continue
		}
		checkFloor(t, path+": "+jose, m[1], securityFloors[jose])
	}
	if checked == 0 {
		t.Fatal("no Go example depends on the Go SDK; the check is not checking anything")
	}
}

// The toolchain that built the test binary is the one that builds the release.
func TestSecurityFloors_Toolchain(t *testing.T) {
	v := strings.TrimPrefix(runtime.Version(), "go")
	if i := strings.IndexAny(v, " -"); i >= 0 {
		v = v[:i]
	}
	checkFloor(t, "toolchain "+runtime.Version(), v, securityFloors["go"])
}

func checkFloor(t *testing.T, what, got, floor string) {
	t.Helper()
	if compareDotted(got, floor) < 0 {
		t.Errorf("%s is %s; the security floor is %s", what, got, floor)
	}
}

// compareDotted compares dotted numeric versions ("1.26.10", "4.1.6"),
// ignoring any pre-release or build suffix. Missing parts count as zero.
func compareDotted(a, b string) int {
	trim := func(s string) []string {
		if i := strings.IndexAny(s, "-+"); i >= 0 {
			s = s[:i]
		}
		return strings.Split(s, ".")
	}
	pa, pb := trim(a), trim(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func TestCompareDotted(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.26.10", "1.26.9", 1},
		{"1.26.9", "1.26.10", -1},
		{"1.27", "1.26.10", 1},
		{"4.1.6", "4.1.6", 0},
		{"0.62.0", "0.61.9", 1},
		{"1.26.10-rc1", "1.26.10", 0},
	} {
		if got := compareDotted(c.a, c.b); got != c.want {
			t.Errorf("compareDotted(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
