package services

import "testing"

func TestStaticResourceLister_List(t *testing.T) {
	resources := []ResourceInfo{
		{URI: "https://api.example.com", Scopes: []string{"read", "write"}, ClientID: "client-1"},
		{URI: "https://other.example.com", Scopes: []string{"admin"}, ClientID: "client-2"},
	}
	lister := NewStaticResourceLister(resources)

	got := lister.List()
	if len(got) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(got))
	}
	if got[0].URI != "https://api.example.com" {
		t.Errorf("expected URI https://api.example.com, got %s", got[0].URI)
	}
	if got[1].ClientID != "client-2" {
		t.Errorf("expected ClientID client-2, got %s", got[1].ClientID)
	}
}

func TestStaticResourceLister_Nil(t *testing.T) {
	lister := NewStaticResourceLister(nil)
	got := lister.List()
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}
