package resource_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
)

func TestResource_Validate_RequiresSlug(t *testing.T) {
	r := resource.Resource{
		ID:          "res-1",
		DisplayName: "Test",
		BackendKind: resource.BackendMint,
	}
	err := r.Validate()
	if !errors.Is(err, domain.ErrInvalidSlug) {
		t.Fatalf("empty slug should yield ErrInvalidSlug, got %v", err)
	}
}

func TestResource_Validate_BrokerProviderConsistency(t *testing.T) {
	t.Run("mint with provider rejected", func(t *testing.T) {
		r := resource.Resource{
			ID:               "res-1",
			Slug:             "mint-with-provider",
			DisplayName:      "Mint",
			BackendKind:      resource.BackendMint,
			BrokerProviderID: "bp-1",
		}
		err := r.Validate()
		if err == nil {
			t.Fatal("expected error for mint resource with broker provider")
		}
		if !strings.Contains(err.Error(), "mint resource must not reference") {
			t.Errorf("error %q does not match mint/provider rejection", err.Error())
		}
	})

	t.Run("broker without provider rejected", func(t *testing.T) {
		r := resource.Resource{
			ID:          "res-2",
			Slug:        "broker-no-provider",
			DisplayName: "Broker",
			BackendKind: resource.BackendBroker,
		}
		err := r.Validate()
		if err == nil {
			t.Fatal("expected error for broker resource without broker provider")
		}
		if !strings.Contains(err.Error(), "broker resource must reference") {
			t.Errorf("error %q does not match broker/no-provider rejection", err.Error())
		}
	})

	t.Run("mint without provider accepted", func(t *testing.T) {
		r := resource.Resource{
			ID:          "res-3",
			Slug:        "good-mint",
			DisplayName: "Mint",
			BackendKind: resource.BackendMint,
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("valid mint should pass, got %v", err)
		}
	})

	t.Run("broker with provider accepted", func(t *testing.T) {
		r := resource.Resource{
			ID:               "res-4",
			Slug:             "good-broker",
			DisplayName:      "Broker",
			BackendKind:      resource.BackendBroker,
			BrokerProviderID: "bp-1",
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("valid broker should pass, got %v", err)
		}
	})

	t.Run("unknown backend kind rejected", func(t *testing.T) {
		r := resource.Resource{
			ID:          "res-5",
			Slug:        "weird",
			DisplayName: "Weird",
			BackendKind: resource.BackendKind("hybrid"),
		}
		if err := r.Validate(); err == nil {
			t.Fatal("expected error for unknown backend_kind")
		}
	})
}

// TestResource_Validate_URI is the regression for audit finding B13.
// Empty URI is allowed (slug is the canonical identifier); when set, URI
// must be an absolute http(s) URL with a host.
func TestResource_Validate_URI(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		ok   bool
	}{
		{"empty allowed", "", true},
		{"valid https", "https://mcp.example.com/api", true},
		{"valid http", "http://localhost:8080", true},
		{"with port + path", "https://api.example.com:443/v1/resource", true},
		{"relative rejected", "/api/resource", false},
		{"missing scheme", "mcp.example.com", false},
		{"unsupported scheme", "ftp://files.example.com", false},
		{"missing host", "https:///path", false},
		{"plain garbage", "not a url at all", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := resource.Resource{
				Slug:        "uri-test",
				BackendKind: resource.BackendMint,
				URI:         tc.uri,
			}
			err := r.Validate()
			if tc.ok && err != nil {
				t.Fatalf("URI %q expected ok, got %v", tc.uri, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("URI %q expected rejection, got nil", tc.uri)
			}
		})
	}
}

// TestResource_Validate_Scopes is the regression for audit finding B14.
// Empty scope name and duplicate names are rejected.
func TestResource_Validate_Scopes(t *testing.T) {
	t.Run("empty list allowed", func(t *testing.T) {
		r := resource.Resource{Slug: "ok", BackendKind: resource.BackendMint}
		if err := r.Validate(); err != nil {
			t.Fatalf("empty scopes should pass: %v", err)
		}
	})

	t.Run("non-empty unique passes", func(t *testing.T) {
		r := resource.Resource{
			Slug:        "ok",
			BackendKind: resource.BackendMint,
			Scopes: []resource.Scope{
				{Name: "read"},
				{Name: "write"},
			},
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("unique scopes should pass: %v", err)
		}
	})

	t.Run("empty scope name rejected", func(t *testing.T) {
		r := resource.Resource{
			Slug:        "bad",
			BackendKind: resource.BackendMint,
			Scopes:      []resource.Scope{{Name: ""}},
		}
		if err := r.Validate(); err == nil {
			t.Fatal("expected error for empty scope name")
		}
	})

	t.Run("duplicate scope name rejected", func(t *testing.T) {
		r := resource.Resource{
			Slug:        "bad",
			BackendKind: resource.BackendMint,
			Scopes: []resource.Scope{
				{Name: "read"},
				{Name: "read"},
			},
		}
		if err := r.Validate(); err == nil {
			t.Fatal("expected error for duplicate scope name")
		}
	})
}

func TestNormalizeSlug_LowercaseAndValidate(t *testing.T) {
	t.Run("lowercases mixed case", func(t *testing.T) {
		got, err := resource.NormalizeSlug("Foo-Bar")
		if err != nil {
			t.Fatalf("expected ok, got %v", err)
		}
		if got != "foo-bar" {
			t.Errorf("got %q, want foo-bar", got)
		}
	})

	t.Run("rejects leading underscore", func(t *testing.T) {
		_, err := resource.NormalizeSlug("_x")
		if !errors.Is(err, domain.ErrInvalidSlug) {
			t.Fatalf("expected ErrInvalidSlug, got %v", err)
		}
	})

	t.Run("rejects 65-char string", func(t *testing.T) {
		_, err := resource.NormalizeSlug(strings.Repeat("a", 65))
		if !errors.Is(err, domain.ErrInvalidSlug) {
			t.Fatalf("expected ErrInvalidSlug, got %v", err)
		}
	})

	t.Run("rejects empty string", func(t *testing.T) {
		_, err := resource.NormalizeSlug("")
		if !errors.Is(err, domain.ErrInvalidSlug) {
			t.Fatalf("expected ErrInvalidSlug, got %v", err)
		}
	})
}

func TestSlugRegex_Bounds(t *testing.T) {
	t.Run("64 chars accepted", func(t *testing.T) {
		got, err := resource.NormalizeSlug(strings.Repeat("a", 64))
		if err != nil {
			t.Fatalf("64-char slug must be accepted, got %v", err)
		}
		if len(got) != 64 {
			t.Errorf("len = %d, want 64", len(got))
		}
	})

	t.Run("first char must be alphanumeric", func(t *testing.T) {
		_, err := resource.NormalizeSlug("-leading-hyphen")
		if !errors.Is(err, domain.ErrInvalidSlug) {
			t.Errorf("leading hyphen should be rejected, got %v", err)
		}
	})

	t.Run("digit first char accepted", func(t *testing.T) {
		got, err := resource.NormalizeSlug("1-resource")
		if err != nil {
			t.Fatalf("digit-first slug must be accepted, got %v", err)
		}
		if got != "1-resource" {
			t.Errorf("got %q, want 1-resource", got)
		}
	})

	t.Run("uppercase normalized then validated", func(t *testing.T) {
		got, err := resource.NormalizeSlug("ABC")
		if err != nil {
			t.Fatalf("uppercase should normalize and pass, got %v", err)
		}
		if got != "abc" {
			t.Errorf("got %q, want abc", got)
		}
	})
}

func TestResource_IsMintIsBroker(t *testing.T) {
	mint := resource.Resource{BackendKind: resource.BackendMint}
	if !mint.IsMint() || mint.IsBroker() {
		t.Errorf("mint flags wrong: IsMint=%v IsBroker=%v", mint.IsMint(), mint.IsBroker())
	}

	broker := resource.Resource{BackendKind: resource.BackendBroker}
	if broker.IsMint() || !broker.IsBroker() {
		t.Errorf("broker flags wrong: IsMint=%v IsBroker=%v", broker.IsMint(), broker.IsBroker())
	}
}
