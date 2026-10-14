//go:build integration_postgres

package postgres_test

import (
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

func TestRevocationStore(t *testing.T) {
	testdata.RunRevocationStoreTests(t, func(t *testing.T) (output.RevocationStore, output.TokenStore, output.ClientStore, output.UserStore) {
		s := testdata.SetupTestPGStores(t, pgContainerDSN)
		return s.Revocation, s.Token, s.Client, s.User
	})
}
