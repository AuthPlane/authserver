//go:build integration_postgres

package postgres_test

import (
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

func TestSubjectMappingStore(t *testing.T) {
	testdata.RunSubjectMappingStoreTests(t, func(t *testing.T) (output.SubjectMappingStore, output.IDPStore) {
		stores := testdata.SetupTestPGStores(t, pgContainerDSN)
		return stores.SubjectMapping, stores.IDP
	})
}
