//go:build integration

package sqlite_test

import (
	"testing"

	"github.com/authplane/authserver/testdata"
)

func TestConsentGrantStore(t *testing.T) {
	testdata.RunConsentGrantStoreTests(t, func(t *testing.T) testdata.ConsentGrantStoreSuiteDeps {
		stores := testdata.SetupTestStores(t)
		return testdata.ConsentGrantStoreSuiteDeps{
			Grants:    stores.ConsentGrant,
			Resources: stores.Resource,
			Users:     stores.User,
			Clients:   stores.Client,
		}
	})
}
