package token

import (
	"reflect"
	"testing"
)

func TestActClaim_Depth_Nil(t *testing.T) {
	var a *ActClaim
	if got := a.Depth(); got != 0 {
		t.Errorf("nil ActClaim.Depth() = %d, want 0", got)
	}
}

func TestActClaim_Depth_One(t *testing.T) {
	a := &ActClaim{Sub: "agent-1"}
	if got := a.Depth(); got != 1 {
		t.Errorf("Depth() = %d, want 1", got)
	}
}

func TestActClaim_Depth_Two(t *testing.T) {
	a := &ActClaim{
		Sub: "agent-2",
		Act: &ActClaim{Sub: "agent-1"},
	}
	if got := a.Depth(); got != 2 {
		t.Errorf("Depth() = %d, want 2", got)
	}
}

func TestActClaim_Depth_Three(t *testing.T) {
	a := &ActClaim{
		Sub: "agent-3",
		Act: &ActClaim{
			Sub: "agent-2",
			Act: &ActClaim{Sub: "agent-1"},
		},
	}
	if got := a.Depth(); got != 3 {
		t.Errorf("Depth() = %d, want 3", got)
	}
}

func TestActClaimToMap_Nil(t *testing.T) {
	if got := ActClaimToMap(nil); got != nil {
		t.Errorf("ActClaimToMap(nil) = %v, want nil", got)
	}
}

func TestActClaimToMap_Simple(t *testing.T) {
	a := &ActClaim{Sub: "agent-1"}
	m := ActClaimToMap(a)
	if m["sub"] != "agent-1" {
		t.Errorf("sub = %v, want agent-1", m["sub"])
	}
	if m["act"] != nil {
		t.Errorf("act should be nil for single-level chain")
	}
}

func TestActClaimToMap_Nested(t *testing.T) {
	a := &ActClaim{
		Sub: "agent-2",
		Act: &ActClaim{Sub: "agent-1"},
	}
	m := ActClaimToMap(a)
	if m["sub"] != "agent-2" {
		t.Errorf("sub = %v, want agent-2", m["sub"])
	}
	nested, ok := m["act"].(map[string]interface{})
	if !ok {
		t.Fatal("act should be a nested map")
	}
	if nested["sub"] != "agent-1" {
		t.Errorf("nested sub = %v, want agent-1", nested["sub"])
	}
}

func TestActClaimFromMap_Nil(t *testing.T) {
	if got := ActClaimFromMap(nil); got != nil {
		t.Errorf("ActClaimFromMap(nil) = %v, want nil", got)
	}
}

func TestActClaimFromMap_Simple(t *testing.T) {
	m := map[string]interface{}{"sub": "agent-1"}
	a := ActClaimFromMap(m)
	if a.Sub != "agent-1" {
		t.Errorf("Sub = %q, want agent-1", a.Sub)
	}
	if a.Act != nil {
		t.Errorf("Act should be nil")
	}
}

func TestActClaimFromMap_Nested(t *testing.T) {
	m := map[string]interface{}{
		"sub": "agent-2",
		"act": map[string]interface{}{"sub": "agent-1"},
	}
	a := ActClaimFromMap(m)
	if a.Sub != "agent-2" {
		t.Errorf("Sub = %q, want agent-2", a.Sub)
	}
	if a.Act == nil || a.Act.Sub != "agent-1" {
		t.Errorf("nested act.Sub = %v, want agent-1", a.Act)
	}
}

func TestActClaimRoundTrip(t *testing.T) {
	original := &ActClaim{
		Sub: "agent-3",
		Act: &ActClaim{
			Sub: "agent-2",
			Act: &ActClaim{Sub: "agent-1"},
		},
	}
	m := ActClaimToMap(original)
	restored := ActClaimFromMap(m)

	if restored.Sub != original.Sub {
		t.Errorf("Sub = %q, want %q", restored.Sub, original.Sub)
	}
	if restored.Act.Sub != original.Act.Sub {
		t.Errorf("Act.Sub = %q, want %q", restored.Act.Sub, original.Act.Sub)
	}
	if restored.Act.Act.Sub != original.Act.Act.Sub {
		t.Errorf("Act.Act.Sub = %q, want %q", restored.Act.Act.Sub, original.Act.Act.Sub)
	}
	if restored.Depth() != original.Depth() {
		t.Errorf("Depth() = %d, want %d", restored.Depth(), original.Depth())
	}
}

// TestActClaimRoundTrip_ExtrasPreserved asserts that arbitrary RFC 8693 §4.1
// identifying claims — client_id, iss, actor_type, custom fields — are
// preserved losslessly at every hop across a FromMap→ToMap round-trip.
func TestActClaimRoundTrip_ExtrasPreserved(t *testing.T) {
	original := map[string]interface{}{
		"sub":        "agent-3",
		"client_id":  "client-3",
		"iss":        "https://auth.example.com",
		"actor_type": "agent",
		"kind":       "x",
		"act": map[string]interface{}{
			"sub":        "agent-2",
			"client_id":  "client-2",
			"iss":        "https://auth.example.com",
			"actor_type": "service",
			"kind":       "x",
			"act": map[string]interface{}{
				"sub":        "agent-1",
				"client_id":  "client-1",
				"iss":        "https://auth.example.com",
				"actor_type": "agent",
				"kind":       "x",
			},
		},
	}

	restored := ActClaimToMap(ActClaimFromMap(original))
	if !reflect.DeepEqual(restored, original) {
		t.Errorf("round-trip lost data:\n got: %#v\nwant: %#v", restored, original)
	}
}

// TestActClaimRoundTrip_ExtrasCannotOverrideStructural asserts that Extras
// cannot spoof the structural sub/act fields on emit — the real Sub and
// nested Act always win.
func TestActClaimRoundTrip_ExtrasCannotOverrideStructural(t *testing.T) {
	a := &ActClaim{
		Sub: "real",
		Act: &ActClaim{Sub: "inner-real"},
		Extras: map[string]interface{}{
			"sub": "spoofed",
			"act": map[string]interface{}{"sub": "spoofed-inner"},
		},
	}
	m := ActClaimToMap(a)
	if m["sub"] != "real" {
		t.Errorf("sub = %v, want real", m["sub"])
	}
	nested, ok := m["act"].(map[string]interface{})
	if !ok {
		t.Fatalf("act should be the nested struct map, got %T", m["act"])
	}
	if nested["sub"] != "inner-real" {
		t.Errorf("act.sub = %v, want inner-real", nested["sub"])
	}
}

// TestActClaimRoundTrip_LosslessForArbitraryExtras pins the lossless
// round-trip property of the domain converter: any keys present on an
// inbound act map other than "sub"/"act" must survive ActClaimFromMap →
// ActClaimToMap unchanged. The payload deliberately uses RFC 8693 §4.1 ¶2
// non-identity claims (exp/nbf/aud/iat/jti) as a sharp example — the
// converter is layer-pure and does not enforce semantics about which
// claims belong inside an act hop. Semantic enforcement (stripping
// non-identity claims) is a separate, explicit step at the service layer.
func TestActClaimRoundTrip_LosslessForArbitraryExtras(t *testing.T) {
	original := map[string]interface{}{
		"sub": "agent-1",
		"exp": float64(1234567890),
		"nbf": float64(1234567800),
		"aud": []interface{}{"https://resource.example.com"},
		"iat": float64(1234567800),
		"jti": "abc",
	}
	restored := ActClaimToMap(ActClaimFromMap(original))
	if !reflect.DeepEqual(restored, original) {
		t.Errorf("non-identity claims not round-tripped:\n got: %#v\nwant: %#v", restored, original)
	}
}

func TestIsValidSubjectTokenType(t *testing.T) {
	tests := []struct {
		tokenType string
		want      bool
	}{
		{TokenTypeAccessToken, true},
		{TokenTypeJWT, true},
		{TokenTypeRefreshToken, false},
		{"invalid", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsValidSubjectTokenType(tt.tokenType); got != tt.want {
			t.Errorf("IsValidSubjectTokenType(%q) = %v, want %v", tt.tokenType, got, tt.want)
		}
	}
}
