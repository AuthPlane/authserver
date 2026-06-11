//go:build integration

package sqlite_test

import (
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

func TestDPoPNonceStore(t *testing.T) {
	testdata.RunDPoPNonceStoreTests(t, func(t *testing.T) output.DPoPNonceStore {
		return testdata.SetupTestStores(t).DPoPNonce
	})
}
