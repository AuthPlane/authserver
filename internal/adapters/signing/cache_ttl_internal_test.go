package signing

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

type swappingStore struct{ current *output.SigningKey }

func (s *swappingStore) LoadCurrent(context.Context) (*output.SigningKey, error) {
	return s.current, nil
}
func (s *swappingStore) LoadPrevious(context.Context) (*output.SigningKey, error) { return nil, nil }
func (s *swappingStore) ListActive(context.Context) ([]*output.SigningKey, error) { return nil, nil }
func (s *swappingStore) Save(context.Context, *output.SigningKey) error           { return nil }
func (s *swappingStore) CreateIfAbsent(context.Context, *output.SigningKey) error { return nil }

// The postgres_key current-key cache expires, so a key change whose
// notification was missed is picked up without one.
func TestSigningKeyCache_Expires(t *testing.T) {
	if signingKeyCacheTTL != 60*time.Second {
		t.Errorf("signingKeyCacheTTL = %v, want 60s", signingKeyCacheTTL)
	}
	inner := &swappingStore{current: &output.SigningKey{KeyID: "old"}}
	store := WrapKeyStore(inner, newSigningKeyCache(50*time.Millisecond), observability.NewNoop())
	ctx := context.Background()
	if k, _ := store.LoadCurrent(ctx); k.KeyID != "old" {
		t.Fatalf("first read = %s, want old", k.KeyID)
	}
	inner.current = &output.SigningKey{KeyID: "new"} // changed, nobody told the cache
	time.Sleep(100 * time.Millisecond)
	if k, _ := store.LoadCurrent(ctx); k.KeyID != "new" {
		t.Errorf("read after the TTL = %s, want new", k.KeyID)
	}
}
