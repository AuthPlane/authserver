package apikey

import (
	"strings"
	"testing"
)

func TestParseConfigData_RoundTripsAdvertisedFields(t *testing.T) {
	raw := []byte(`{
		"header_name": "X-API-Key",
		"header_prefix": "",
		"issuance_instructions_url": "https://platform.openai.com/api-keys"
	}`)
	cfg, err := parseConfigData(raw)
	if err != nil {
		t.Fatalf("parseConfigData: %v", err)
	}
	if cfg.HeaderName != "X-API-Key" {
		t.Errorf("HeaderName = %q, want X-API-Key", cfg.HeaderName)
	}
	if cfg.HeaderPrefix != "" {
		t.Errorf("HeaderPrefix = %q, want empty", cfg.HeaderPrefix)
	}
	if cfg.IssuanceInstructionsURL != "https://platform.openai.com/api-keys" {
		t.Errorf("IssuanceInstructionsURL = %q, want OpenAI URL", cfg.IssuanceInstructionsURL)
	}
}

func TestParseConfigData_RejectsMissingHeaderName(t *testing.T) {
	// header_name is the only field the adapter requires — without it the
	// downstream consumer can't format the upstream call.
	raw := []byte(`{"header_prefix": "Bearer "}`)
	_, err := parseConfigData(raw)
	if err == nil {
		t.Fatal("expected error for missing header_name, got nil")
	}
	if !strings.Contains(err.Error(), "header_name") {
		t.Errorf("error = %v, want to mention header_name", err)
	}
}

func TestParseConfigData_RejectsEmpty(t *testing.T) {
	if _, err := parseConfigData(nil); err == nil {
		t.Fatal("expected error for nil config_data, got nil")
	}
	if _, err := parseConfigData([]byte{}); err == nil {
		t.Fatal("expected error for empty config_data, got nil")
	}
}

func TestParseConfigData_RejectsMalformedJSON(t *testing.T) {
	if _, err := parseConfigData([]byte(`{not json`)); err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}
