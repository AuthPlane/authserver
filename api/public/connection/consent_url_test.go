package connectionapi

import (
	"net/url"
	"testing"
)

func TestConsentURL(t *testing.T) {
	tests := []struct {
		name         string
		base         string
		providerSlug string
		resourceSlug string
		want         string
	}{
		{
			name:         "happy path with resource",
			base:         "https://auth.example.com",
			providerSlug: "github",
			resourceSlug: "github-repo",
			want:         "https://auth.example.com/connect/github?resource=github-repo&return_url=" + url.QueryEscape("https://auth.example.com/connections"),
		},
		{
			name:         "trailing slash on base is normalized",
			base:         "https://auth.example.com/",
			providerSlug: "github",
			resourceSlug: "github-repo",
			want:         "https://auth.example.com/connect/github?resource=github-repo&return_url=" + url.QueryEscape("https://auth.example.com/connections"),
		},
		{
			name:         "empty base returns empty",
			base:         "",
			providerSlug: "github",
			resourceSlug: "github-repo",
			want:         "",
		},
		{
			name:         "empty base with trailing slash still empty",
			base:         "/",
			providerSlug: "github",
			resourceSlug: "github-repo",
			want:         "",
		},
		{
			name:         "localhost base",
			base:         "http://localhost:9000",
			providerSlug: "linear",
			resourceSlug: "linear-issues",
			want:         "http://localhost:9000/connect/linear?resource=linear-issues&return_url=" + url.QueryEscape("http://localhost:9000/connections"),
		},
		{
			name:         "empty resource slug omits resource param",
			base:         "https://auth.example.com",
			providerSlug: "github",
			resourceSlug: "",
			want:         "https://auth.example.com/connect/github?return_url=" + url.QueryEscape("https://auth.example.com/connections"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ConsentURL(tt.base, tt.providerSlug, tt.resourceSlug); got != tt.want {
				t.Errorf("ConsentURL(%q, %q, %q) = %q, want %q", tt.base, tt.providerSlug, tt.resourceSlug, got, tt.want)
			}
		})
	}
}
