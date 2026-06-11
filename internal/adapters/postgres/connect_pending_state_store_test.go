//go:build integration_postgres

package postgres_test

import (
	"testing"

	"github.com/authplane/authserver/testdata"
)

func TestConnectPendingStateStore(t *testing.T) {
	testdata.RunConnectPendingStateStoreTests(t, func(t *testing.T) testdata.ConnectPendingStateStoreSuiteDeps {
		stores := testdata.SetupTestPGStores(t, pgContainerDSN)
		return testdata.ConnectPendingStateStoreSuiteDeps{
			States:    stores.ConnectPendingState,
			Providers: stores.BrokerProvider,
			Resources: stores.Resource,
		}
	})
}
