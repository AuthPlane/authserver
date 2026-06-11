package sqlite_test

import (
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

func TestIdPStore(t *testing.T) {
	testdata.RunIdPStoreTests(t, func(t *testing.T) output.IDPStore {
		return testdata.SetupTestStores(t).IDP
	})
}
