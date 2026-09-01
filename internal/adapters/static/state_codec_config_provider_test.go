package static_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/authplane/authserver/internal/adapters/static"
)

func TestStateCodecConfigProvider_ReturnsKey(t *testing.T) {
	p := static.NewStateCodecConfigProvider([]byte("a-signing-key"))
	cfg, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if !bytes.Equal(cfg.Key, []byte("a-signing-key")) {
		t.Fatalf("unexpected key: %q", cfg.Key)
	}
}

func TestNewStateCodecConfigProvider_EmptyKey_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on empty key, got nil")
		}
	}()
	static.NewStateCodecConfigProvider([]byte{})
}

func TestNewStateCodecConfigProvider_DefensiveCopy(t *testing.T) {
	key := []byte("original-key-bytes")
	p := static.NewStateCodecConfigProvider(key)
	for i := range key { // mutate caller buffer
		key[i] = 'X'
	}
	cfg, _ := p.Config(context.Background())
	if bytes.Equal(cfg.Key, key) {
		t.Fatal("provider key mutated when caller modified the buffer")
	}
}
