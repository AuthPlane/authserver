//go:build integration

package sqlite_test

import (
	"testing"

	"github.com/authplane/authserver/testdata"
)

func TestBrokerProviderStore(t *testing.T) {
	testdata.RunBrokerProviderStoreTests(t, func(t *testing.T) testdata.BrokerProviderStoreSuiteDeps {
		db := testdata.SetupTestDB(t)
		stores := db.NewStores()
		return testdata.BrokerProviderStoreSuiteDeps{
			Providers:       stores.BrokerProvider,
			Resources:       stores.Resource,
			Users:           stores.User,
			SeedBrokerGrant: sqliteSeedBrokerGrant(t, db),
		}
	})
}
