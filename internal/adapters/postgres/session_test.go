//go:build integration_postgres

package postgres_test

import (
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

func TestSessionStore(t *testing.T) {
	testdata.RunSessionStoreTests(t, func(t *testing.T) output.SessionStore {
		return testdata.SetupTestPGStores(t, pgContainerDSN).Session
	})
}
