package sqlite_test

import (
	"testing"

	"github.com/authplane/authserver/testdata"
)

// TestFrontingLinkStore exercises the sqlite FrontingLinkStore against the
// shared integration suite. Default-build (no integration tag) so
// CI runs it on every push — the in-memory sqlite path is fast.
func TestFrontingLinkStore(t *testing.T) {
	testdata.RunFrontingLinkStoreTests(t, func(t *testing.T) testdata.FrontingLinkStoreSuiteDeps {
		db := testdata.SetupTestDB(t)
		stores := db.NewStores()
		return testdata.FrontingLinkStoreSuiteDeps{
			Links:     stores.FrontingLink,
			Resources: stores.Resource,
			Providers: stores.BrokerProvider,
		}
	})
}
