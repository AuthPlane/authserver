package cimd

import (
	"strings"
	"testing"
)

// The address policy is part of the key so that a document, a failure or a
// flight produced with filtering off does not answer a request that has it on.
// For a hostname the URL-level check defers to the dial, and a cache hit — or a
// shared flight — skips the dial, so the key is where the two policies have to
// be kept apart.
func TestFetchKey_SeparatesAddressPolicies(t *testing.T) {
	const docURL = "http://metadata.example.com/client.json"

	filtered := fetchKey(docURL, false)
	unfiltered := fetchKey(docURL, true)

	if filtered == unfiltered {
		t.Fatalf("both policies share the key %q for %s", filtered, docURL)
	}

	// Distinct prefixes are not enough: the key is a prefix followed by the URL,
	// so if one prefix were a prefix of the other, a URL beginning with the
	// remainder would produce the opposite policy's key. Derived from fetchKey's
	// own output rather than the literals, so a rename cannot leave this passing
	// on strings the function no longer uses.
	filteredPrefix := strings.TrimSuffix(filtered, docURL)
	unfilteredPrefix := strings.TrimSuffix(unfiltered, docURL)
	if strings.HasPrefix(filteredPrefix, unfilteredPrefix) || strings.HasPrefix(unfilteredPrefix, filteredPrefix) {
		t.Errorf("policy prefixes %q and %q: one is a prefix of the other, so a URL can forge the opposite key", filteredPrefix, unfilteredPrefix)
	}
	if filtered != fetchKey(docURL, false) {
		t.Error("the same URL and policy must produce the same key")
	}
	if unfiltered != fetchKey(docURL, true) {
		t.Error("the same URL and policy must produce the same key")
	}
	if !strings.Contains(filtered, docURL) || !strings.Contains(unfiltered, docURL) {
		t.Error("the key must carry the URL")
	}
	if fetchKey(docURL, false) == fetchKey("http://metadata.example.com/other.json", false) {
		t.Error("different URLs under one policy must not share a key")
	}
}
