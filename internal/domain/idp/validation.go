package idp

import (
	"fmt"
	"net/url"
)

// Validate checks that the TrustedIDP fields meet domain invariants.
func (idp *TrustedIDP) Validate() error {
	if idp.Name == "" {
		return fmt.Errorf("name is required")
	}
	if err := validateHTTPSURL(idp.Issuer, "issuer"); err != nil {
		return err
	}
	if idp.JWKSUri != "" {
		if err := validateHTTPSURL(idp.JWKSUri, "jwks_uri"); err != nil {
			return err
		}
	}
	if idp.Audience == "" {
		return fmt.Errorf("audience is required")
	}
	return nil
}

// validateHTTPSURL checks that a URL is valid and uses the HTTPS scheme.
func validateHTTPSURL(raw, field string) error {
	if raw == "" {
		return fmt.Errorf("%s is required", field)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", field, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%s must use HTTPS scheme", field)
	}
	if u.Host == "" {
		return fmt.Errorf("%s must have a host", field)
	}
	return nil
}
