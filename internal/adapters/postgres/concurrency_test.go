//go:build integration_postgres

package postgres_test

import (
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

func TestClientOptimisticLocking(t *testing.T) {
	testdata.RunClientOptimisticLockTests(t, func(t *testing.T) output.ClientStore {
		return testdata.SetupTestPGStores(t, pgContainerDSN).Client
	})
}

func TestUserOptimisticLocking(t *testing.T) {
	testdata.RunUserOptimisticLockTests(t, func(t *testing.T) output.UserStore {
		return testdata.SetupTestPGStores(t, pgContainerDSN).User
	})
}

func TestTransactionManager(t *testing.T) {
	testdata.RunTransactionManagerTests(t, func(t *testing.T) testdata.TransactionStores {
		stores := testdata.SetupTestPGStores(t, pgContainerDSN)
		return testdata.TransactionStores{
			Client:      stores.Client,
			User:        stores.User,
			Transaction: stores.TransactionMgr,
		}
	})
}
