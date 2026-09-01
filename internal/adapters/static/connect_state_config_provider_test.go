package static_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/authplane/authserver/internal/adapters/static"
)

func TestConnectStateConfigProvider_ReturnsKey(t *testing.T) {
	p := static.NewConnectStateConfigProvider([]byte("a-connect-state-key"))
	cfg, err := p.Config(context.Background())
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if !bytes.Equal(cfg.Key, []byte("a-connect-state-key")) {
		t.Fatalf("unexpected key: %q", cfg.Key)
	}
}

func TestNewConnectStateConfigProvider_EmptyKey_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on empty key, got nil")
		}
	}()
	static.NewConnectStateConfigProvider([]byte{})
}

func TestNewConnectStateConfigProvider_DefensiveCopy(t *testing.T) {
	key := []byte("original-key-bytes")
	p := static.NewConnectStateConfigProvider(key)
	for i := range key { // mutate caller buffer
		key[i] = 'X'
	}
	cfg, _ := p.Config(context.Background())
	if bytes.Equal(cfg.Key, key) {
		t.Fatal("provider key mutated when caller modified the buffer")
	}
}

func TestConnectStateConfigProvider_Config_ReturnsIndependentCopy(t *testing.T) {
	p := static.NewConnectStateConfigProvider([]byte("a-connect-state-key"))
	cfg, _ := p.Config(context.Background())
	for i := range cfg.Key { // mutate the returned slice
		cfg.Key[i] = 'X'
	}
	again, _ := p.Config(context.Background())
	if !bytes.Equal(again.Key, []byte("a-connect-state-key")) {
		t.Fatalf("stored key corrupted by mutating a returned slice: %q", again.Key)
	}
}
