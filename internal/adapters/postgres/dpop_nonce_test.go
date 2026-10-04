//go:build integration_postgres

package postgres_test

import (
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

func TestDPoPNonceStore(t *testing.T) {
	testdata.RunDPoPNonceStoreTests(t, func(t *testing.T) output.DPoPNonceStore {
		return testdata.SetupTestPGStores(t, pgContainerDSN).DPoPNonce
	})
}
