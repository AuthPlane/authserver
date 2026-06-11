//go:build integration_postgres

package postgres_test

import (
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

func TestAssertionJTIStore(t *testing.T) {
	testdata.RunAssertionJTIStoreTests(t, func(t *testing.T) output.AssertionJTIStore {
		return testdata.SetupTestPGStores(t, pgContainerDSN).AssertionJTI
	})
}
