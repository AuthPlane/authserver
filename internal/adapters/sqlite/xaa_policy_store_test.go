package sqlite_test

import (
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

func TestXAAPolicyStore(t *testing.T) {
	testdata.RunXAAPolicyStoreTests(t, func(t *testing.T) (output.XAAPolicyStore, output.IDPStore) {
		stores := testdata.SetupTestStores(t)
		return stores.XAAPolicy, stores.IDP
	})
}
