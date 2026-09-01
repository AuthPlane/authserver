//go:build integration

package sqlite_test

import (
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

func TestClientOptimisticLocking(t *testing.T) {
	testdata.RunClientOptimisticLockTests(t, func(t *testing.T) output.ClientStore {
		return testdata.SetupTestStores(t).Client
	})
}

func TestUserOptimisticLocking(t *testing.T) {
	testdata.RunUserOptimisticLockTests(t, func(t *testing.T) output.UserStore {
		return testdata.SetupTestStores(t).User
	})
}

func TestTransactionManager(t *testing.T) {
	testdata.RunTransactionManagerTests(t, func(t *testing.T) testdata.TransactionStores {
		stores := testdata.SetupTestStores(t)
		return testdata.TransactionStores{
			Client:         stores.Client,
			User:           stores.User,
			BrokerProvider: stores.BrokerProvider,
			BrokerGrant:    stores.BrokerGrant,
			Transaction:    stores.TransactionMgr,
		}
	})
}
