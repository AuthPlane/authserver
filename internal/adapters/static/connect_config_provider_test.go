package static

import (
	"context"
	"reflect"
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
)

func TestConnectConfigProvider_ReturnsConfig(t *testing.T) {
	want := output.ConnectConfig{
		AllowedReturnURLs: []string{"https://a.example", "https://b.example"},
		RedirectBaseURL:   "https://auth.example.com",
	}
	p := NewConnectConfigProvider(want)
	got, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestConnectConfigProvider_DefensiveCopy(t *testing.T) {
	src := []string{"https://a.example"}
	p := NewConnectConfigProvider(output.ConnectConfig{AllowedReturnURLs: src})
	src[0] = "https://evil.example" // mutate caller's slice
	got, _ := p.Config(context.Background())
	if got.AllowedReturnURLs[0] != "https://a.example" {
		t.Fatalf("provider did not defensively copy: got %q", got.AllowedReturnURLs[0])
	}
}
