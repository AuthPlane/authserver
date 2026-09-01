//go:build integration

package services_test

import "context"

// staticIssuerForTest is an integration-test-local implementation of
// output.IssuerProvider that returns a fixed string for every call. It
// avoids importing internal/adapters/static from integration tests,
// which would violate Gate 0 (one-way-ratchet that forbids new
// internal/ imports in integration tests).
type staticIssuerForTest string

func (s staticIssuerForTest) Issuer(_ context.Context) (string, error) { return string(s), nil }
