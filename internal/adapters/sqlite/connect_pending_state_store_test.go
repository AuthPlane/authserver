//go:build integration

package sqlite_test

import (
	"testing"

	"github.com/authplane/authserver/testdata"
)

func TestConnectPendingStateStore(t *testing.T) {
	testdata.RunConnectPendingStateStoreTests(t, func(t *testing.T) testdata.ConnectPendingStateStoreSuiteDeps {
		stores := testdata.SetupTestStores(t)
		return testdata.ConnectPendingStateStoreSuiteDeps{
			States:    stores.ConnectPendingState,
			Providers: stores.BrokerProvider,
			Resources: stores.Resource,
		}
	})
}
