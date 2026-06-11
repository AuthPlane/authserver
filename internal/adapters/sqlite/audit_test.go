//go:build integration

package sqlite_test

import (
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

func TestAuditStore(t *testing.T) {
	testdata.RunAuditStoreTests(t, func(t *testing.T) output.AuditStore {
		return testdata.SetupTestStores(t).Audit
	})
}
