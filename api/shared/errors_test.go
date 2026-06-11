package shared

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestWriteOAuthError_OmitsConsentURL(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteOAuthError(rec, 400, "invalid_grant", "bad grant")

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, has := raw["consent_url"]; has {
		t.Error("consent_url should be absent when using WriteOAuthError")
	}
	if raw["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", raw["error"])
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
}

func TestWriteOAuthErrorWithConsent(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteOAuthErrorWithConsent(rec, 400,
		"consent_required",
		"Authorize access to google-calendar",
		"https://as.example.com/connect/google-calendar")

	if rec.Code != 400 {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}

	var resp OAuthErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error != "consent_required" {
		t.Errorf("Error = %q, want consent_required", resp.Error)
	}
	if resp.ErrorDescription != "Authorize access to google-calendar" {
		t.Errorf("ErrorDescription = %q", resp.ErrorDescription)
	}
	if resp.ConsentURL != "https://as.example.com/connect/google-calendar" {
		t.Errorf("ConsentURL = %q", resp.ConsentURL)
	}
	if resp.Type != "https://docs.authplane.ai/errors/consent_required" {
		t.Errorf("Type = %q", resp.Type)
	}
	if resp.Status != 400 {
		t.Errorf("Status = %d, want 400", resp.Status)
	}
}

//  — round-trip the new cause field. Ensures the wire-format change
// is observable by SDKs that decode OAuthErrorResponse directly, and
// confirms the field is omitted when the caller did not supply it.

func TestWriteOAuthErrorWithConsentAndCause_RoundTripsCauseField(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteOAuthErrorWithConsentAndCause(rec, 400,
		"consent_required",
		"Authorize access to test-mcp",
		"https://as.example.com/authorize?resource=test-mcp",
		"scope_insufficient",
	)

	var resp OAuthErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Cause != "scope_insufficient" {
		t.Errorf("Cause = %q, want scope_insufficient", resp.Cause)
	}
	if resp.ConsentURL != "https://as.example.com/authorize?resource=test-mcp" {
		t.Errorf("ConsentURL = %q", resp.ConsentURL)
	}
	if resp.Error != "consent_required" {
		t.Errorf("Error = %q, want consent_required", resp.Error)
	}
}

func TestWriteOAuthErrorWithConsentAndCause_OmitCauseWhenEmpty(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteOAuthErrorWithConsentAndCause(rec, 400,
		"consent_required",
		"Authorize access to thing",
		"https://as.example.com/connect/thing",
		"", // empty cause
	)
	// Decode into a map so we can distinguish "missing" from "present and
	// empty". omitempty strips empty strings from the wire response.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, has := raw["cause"]; has {
		t.Errorf("cause should be omitted when empty, got %v", raw["cause"])
	}
}

func TestWriteOAuthErrorWithConsent_LegacyHelperOmitsCause(t *testing.T) {
	// The legacy WriteOAuthErrorWithConsent is a thin wrapper around
	// WriteOAuthErrorWithConsentAndCause(..., ""). Existing call sites
	// outside the consent path must continue to emit responses WITHOUT
	// the cause field on the wire.
	rec := httptest.NewRecorder()
	WriteOAuthErrorWithConsent(rec, 400,
		"consent_required",
		"Authorize access to thing",
		"https://as.example.com/connect/thing")

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, has := raw["cause"]; has {
		t.Errorf("legacy WriteOAuthErrorWithConsent should not emit cause, got %v", raw["cause"])
	}
	if raw["consent_url"] != "https://as.example.com/connect/thing" {
		t.Errorf("consent_url = %v", raw["consent_url"])
	}
}
