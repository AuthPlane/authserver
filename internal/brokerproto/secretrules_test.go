package brokerproto

import (
	"strings"
	"testing"
)

func TestValidEnvVarName(t *testing.T) {
	accept := []string{
		"CONNECTOR_GITHUB_SECRET",
		"AUTHPLANE_VAULT_GOOGLE_CLIENT_SECRET",
		"CONNECTOR_X",
		"CONNECTOR_E2E_MOCK_SECRET",
	}
	for _, s := range accept {
		t.Run("accept/"+s, func(t *testing.T) {
			if !ValidEnvVarName(s) {
				t.Errorf("ValidEnvVarName(%q) = false, want true", s)
			}
		})
	}

	reject := map[string]string{
		"empty":           "",
		"lowercase":       "connector_github",
		"wrong_prefix":    "FOO_BAR",
		"leading_digit":   "CONNECTOR_1FOO",
		"trailing_dollar": "CONNECTOR_FOO$",
	}
	for name, s := range reject {
		t.Run("reject/"+name, func(t *testing.T) {
			if ValidEnvVarName(s) {
				t.Errorf("ValidEnvVarName(%q) = true, want false", s)
			}
		})
	}
}

func TestReservedAuthParams_Coverage(t *testing.T) {
	required := []string{
		"client_id", "client_secret", "response_type", "state",
		"code_challenge", "code_challenge_method", "redirect_uri", "scope",
	}
	for _, k := range required {
		if _, ok := ReservedAuthParams[k]; !ok {
			t.Errorf("ReservedAuthParams missing required key %q", k)
		}
	}
}

func TestValidateExtraAuthParams_Valid(t *testing.T) {
	if err := ValidateExtraAuthParams(map[string]string{
		"access_type": "offline",
		"prompt":      "consent",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateExtraAuthParams_RejectsReserved(t *testing.T) {
	for k := range ReservedAuthParams {
		t.Run(k, func(t *testing.T) {
			if err := ValidateExtraAuthParams(map[string]string{k: "evil"}); err == nil {
				t.Fatalf("expected error for reserved key %q, got nil", k)
			}
		})
	}
}

func TestValidateExtraAuthParams_RejectsEmptyKey(t *testing.T) {
	if err := ValidateExtraAuthParams(map[string]string{"": "x"}); err == nil {
		t.Fatal("expected error for empty key, got nil")
	}
}

func TestValidateExtraAuthParams_RejectsTooManyEntries(t *testing.T) {
	params := make(map[string]string, MaxExtraAuthParams+1)
	for i := 0; i <= MaxExtraAuthParams; i++ {
		params["k"+string(rune('a'+i))] = "v"
	}
	err := ValidateExtraAuthParams(params)
	if err == nil || !strings.Contains(err.Error(), "too many entries") {
		t.Fatalf("expected too-many-entries error, got %v", err)
	}
}

func TestValidateExtraAuthParams_RejectsOversizedKey(t *testing.T) {
	longKey := strings.Repeat("k", MaxExtraAuthParamKeyLen+1)
	err := ValidateExtraAuthParams(map[string]string{longKey: "v"})
	if err == nil || !strings.Contains(err.Error(), "key too long") {
		t.Fatalf("expected key-too-long error, got %v", err)
	}
}

func TestValidateExtraAuthParams_RejectsOversizedValue(t *testing.T) {
	longVal := strings.Repeat("v", MaxExtraAuthParamValueLen+1)
	err := ValidateExtraAuthParams(map[string]string{"access_type": longVal})
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("expected value-too-long error, got %v", err)
	}
}
