//go:build integration_postgres

package postgres_test

import (
	"testing"

	"github.com/authplane/authserver/testdata"
)

func TestBrokerProviderStore(t *testing.T) {
	testdata.RunBrokerProviderStoreTests(t, func(t *testing.T) testdata.BrokerProviderStoreSuiteDeps {
		db := testdata.SetupTestPGDB(t, pgContainerDSN)
		stores := db.NewStores()
		return testdata.BrokerProviderStoreSuiteDeps{
			Providers:       stores.BrokerProvider,
			Resources:       stores.Resource,
			Users:           stores.User,
			SeedBrokerGrant: pgSeedBrokerGrant(t, db),
		}
	})
}
