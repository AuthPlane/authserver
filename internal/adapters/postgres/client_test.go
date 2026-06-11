//go:build integration_postgres

package postgres_test

import (
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

func TestClientStore(t *testing.T) {
	testdata.RunClientStoreTests(t, func(t *testing.T) output.ClientStore {
		return testdata.SetupTestPGStores(t, pgContainerDSN).Client
	})
}
