package domain

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestAllSentinelErrorsHaveCodes(t *testing.T) {
	sentinels := []struct {
		name string
		err  *domainError
		code string
	}{
		{"ErrInvalidGrant", ErrInvalidGrant, "invalid_grant"},
		{"ErrInvalidClient", ErrInvalidClient, "invalid_client"},
		{"ErrInvalidScope", ErrInvalidScope, "invalid_scope"},
		{"ErrCodeConsumed", ErrCodeConsumed, "invalid_grant"},
		{"ErrFamilyRevoked", ErrFamilyRevoked, "invalid_grant"},
		{"ErrConsentRequired", ErrConsentRequired, "consent_required"},
		{"ErrSessionExpired", ErrSessionExpired, "invalid_grant"},
		{"ErrInvalidRedirectURI", ErrInvalidRedirectURI, "invalid_request"},
		{"ErrInvalidPKCE", ErrInvalidPKCE, "invalid_grant"},
		{"ErrClientSuspended", ErrClientSuspended, "invalid_client"},
		{"ErrRateLimited", ErrRateLimited, "slow_down"},
		{"ErrUserNotFound", ErrUserNotFound, CodeNotFound},
		{"ErrClientNotFound", ErrClientNotFound, CodeNotFound},
		{"ErrInvalidCredentials", ErrInvalidCredentials, "invalid_grant"},
		{"ErrUnsupportedGrantType", ErrUnsupportedGrantType, "unsupported_grant_type"},
		{"ErrCIMDFetchFailed", ErrCIMDFetchFailed, "invalid_client"},
		{"ErrCIMDInvalid", ErrCIMDInvalid, "invalid_client"},
		// Phase 3
		{"ErrUnauthorizedClient", ErrUnauthorizedClient, "unauthorized_client"},
		{"ErrDPoPReplay", ErrDPoPReplay, "invalid_dpop_proof"},
		{"ErrDPoPInvalidProof", ErrDPoPInvalidProof, "invalid_dpop_proof"},
		{"ErrDPoPNonceRequired", ErrDPoPNonceRequired, "use_dpop_nonce"},
		{"ErrDPoPNonceMismatch", ErrDPoPNonceMismatch, "use_dpop_nonce"},
		{"ErrTokenExchangeNotAuthorized", ErrTokenExchangeNotAuthorized, "access_denied"},
		{"ErrTokenExchangeChainTooDeep", ErrTokenExchangeChainTooDeep, "access_denied"},
	}

	for _, s := range sentinels {
		t.Run(s.name, func(t *testing.T) {
			if s.err.Code() != s.code {
				t.Errorf("Code() = %q, want %q", s.err.Code(), s.code)
			}
			if s.err.Error() == "" {
				t.Error("Error() is empty")
			}
		})
	}
}

func TestIsError(t *testing.T) {
	if !IsError(ErrInvalidGrant) {
		t.Error("IsError should return true for domain errors")
	}
	if IsError(fmt.Errorf("random error")) {
		t.Error("IsError should return false for non-domain errors")
	}
}

func TestErrorCode(t *testing.T) {
	if code := ErrorCode(ErrInvalidClient); code != "invalid_client" {
		t.Errorf("ErrorCode = %q, want invalid_client", code)
	}
	if code := ErrorCode(fmt.Errorf("random")); code != "server_error" {
		t.Errorf("ErrorCode = %q, want server_error", code)
	}
}

func TestWrappedError(t *testing.T) {
	wrapped := fmt.Errorf("context: %w", ErrInvalidGrant)
	if !IsError(wrapped) {
		t.Error("IsError should detect wrapped domain errors")
	}
	if ErrorCode(wrapped) != "invalid_grant" {
		t.Errorf("ErrorCode should extract code from wrapped error")
	}
	if !errors.Is(wrapped, ErrInvalidGrant) {
		t.Error("errors.Is should match wrapped sentinel")
	}
}

func TestConsentRequiredError(t *testing.T) {
	err := &ConsentRequiredError{
		Service: "google-calendar",
	}

	if err.Code() != "consent_required" {
		t.Errorf("Code() = %q, want %q", err.Code(), "consent_required")
	}

	want := "Authorize access to google-calendar"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}

	if !IsError(err) {
		t.Error("IsError should return true for ConsentRequiredError")
	}

	if ErrorCode(err) != "consent_required" {
		t.Errorf("ErrorCode() = %q, want %q", ErrorCode(err), "consent_required")
	}

	// errors.As support
	wrapped := fmt.Errorf("wrap: %w", err)
	var target *ConsentRequiredError
	if !errors.As(wrapped, &target) {
		t.Fatal("errors.As should unwrap ConsentRequiredError")
	}
	if target.Service != "google-calendar" {
		t.Errorf("Service = %q, want %q", target.Service, "google-calendar")
	}
}

func TestConsentRequiredError_DeniedReason_Roundtrip(t *testing.T) {
	e := &ConsentRequiredError{
		ResourceSlug: "google-cal",
		Cause:        CauseConsentMissing,
		DeniedReason: "invalid_grant",
	}
	if e.DeniedReason != "invalid_grant" {
		t.Errorf("DeniedReason = %q, want %q", e.DeniedReason, "invalid_grant")
	}
	// Error() unaffected by DeniedReason — DeniedReason is internal-only.
	if got := e.Error(); !strings.Contains(got, "google-cal") {
		t.Errorf("Error() = %q, want it to contain ResourceSlug", got)
	}
}

// ErrReuseRevocationFailed must be a distinct identity (errors.Is tells the
// two reuse outcomes apart) with ErrFamilyRevoked's code and message (the
// wire must not tell them apart, and a domain error's message is wire text).
func TestReuseRevocationFailed_SameWireAsFamilyRevoked(t *testing.T) {
	if errors.Is(ErrReuseRevocationFailed, ErrFamilyRevoked) || errors.Is(ErrFamilyRevoked, ErrReuseRevocationFailed) {
		t.Fatal("ErrReuseRevocationFailed and ErrFamilyRevoked must be distinct identities")
	}
	if ErrReuseRevocationFailed.Error() != ErrFamilyRevoked.Error() {
		t.Errorf("message = %q, want ErrFamilyRevoked's %q", ErrReuseRevocationFailed.Error(), ErrFamilyRevoked.Error())
	}
	if ErrorCode(ErrReuseRevocationFailed) != ErrorCode(ErrFamilyRevoked) {
		t.Errorf("code = %q, want %q", ErrorCode(ErrReuseRevocationFailed), ErrorCode(ErrFamilyRevoked))
	}
}
