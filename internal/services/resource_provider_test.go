package services

import (
	"context"
	"testing"
)

func TestStaticResourceLister_List(t *testing.T) {
	resources := []ResourceInfo{
		{URI: "https://api.example.com", Scopes: []string{"read", "write"}},
		{URI: "https://other.example.com", Scopes: []string{"admin"}},
	}
	lister := NewStaticResourceLister(resources)

	got, err := lister.List(context.Background())
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(got))
	}
	if got[0].URI != "https://api.example.com" {
		t.Errorf("expected URI https://api.example.com, got %s", got[0].URI)
	}
	if got[1].URI != "https://other.example.com" {
		t.Errorf("expected URI https://other.example.com, got %s", got[1].URI)
	}
}

func TestStaticResourceLister_Nil(t *testing.T) {
	lister := NewStaticResourceLister(nil)
	got, err := lister.List(context.Background())
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}
