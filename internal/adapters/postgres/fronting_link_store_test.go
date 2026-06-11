//go:build integration_postgres

package postgres_test

import (
	"testing"

	"github.com/authplane/authserver/testdata"
)

// TestFrontingLinkStore exercises the postgres FrontingLinkStore against the
// shared integration suite. Build-tagged like the other postgres
// integration tests; runs against a live container in CI.
func TestFrontingLinkStore(t *testing.T) {
	testdata.RunFrontingLinkStoreTests(t, func(t *testing.T) testdata.FrontingLinkStoreSuiteDeps {
		db := testdata.SetupTestPGDB(t, pgContainerDSN)
		stores := db.NewStores()
		return testdata.FrontingLinkStoreSuiteDeps{
			Links:     stores.FrontingLink,
			Resources: stores.Resource,
			Providers: stores.BrokerProvider,
		}
	})
}
