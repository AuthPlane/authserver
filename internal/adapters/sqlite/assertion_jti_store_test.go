package sqlite_test

import (
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

func TestAssertionJTIStore(t *testing.T) {
	testdata.RunAssertionJTIStoreTests(t, func(t *testing.T) output.AssertionJTIStore {
		return testdata.SetupTestStores(t).AssertionJTI
	})
}
