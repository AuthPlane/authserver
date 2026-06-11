//go:build integration_postgres

package postgres_test

import (
	"testing"

	"github.com/authplane/authserver/testdata"
)

func TestBrokerGrantStore(t *testing.T) {
	testdata.RunBrokerGrantStoreTests(t, func(t *testing.T) testdata.BrokerGrantStoreSuiteDeps {
		stores := testdata.SetupTestPGStores(t, pgContainerDSN)
		return testdata.BrokerGrantStoreSuiteDeps{
			Grants:    stores.BrokerGrant,
			Providers: stores.BrokerProvider,
			Users:     stores.User,
		}
	})
}
