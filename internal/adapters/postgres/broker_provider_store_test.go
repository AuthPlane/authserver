//go:build integration_postgres

package postgres_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/testdata"
)

func TestBrokerProviderStore(t *testing.T) {
	testdata.RunBrokerProviderStoreTests(t, func(t *testing.T) testdata.BrokerProviderStoreSuiteDeps {
		db := testdata.SetupTestPGDB(t, pgContainerDSN)
		stores := db.NewStores()
		return testdata.BrokerProviderStoreSuiteDeps{
			Providers:       stores.BrokerProvider,
			Resources:       stores.Resource,
			Users:           stores.User,
			SeedBrokerGrant: pgSeedBrokerGrant(t, db),
		}
	})
}

// TestBrokerProviderStore_EncSecretPairingConstraint verifies that the
// enc_secret_pairing CHECK fires when enc_secret_data is set but
// enc_secret_backend is NULL (half-pair). This is a raw INSERT to bypass
// store-layer validation which always sets both together.
func TestBrokerProviderStore_EncSecretPairingConstraint(t *testing.T) {
	db := testdata.SetupTestPGDB(t, pgContainerDSN)
	ctx := context.Background()
	now := time.Now().UTC()

	_, err := db.Pool.Exec(ctx,
		`INSERT INTO broker_providers
		 (id, slug, display_name, protocol, config_data,
		  enc_secret_data, enc_secret_backend, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, '{}'::jsonb, $5, NULL, $6, $6)`,
		"p-check-violation", "check-violation", "CHECK Violation", "oauth",
		[]byte{0xca, 0xfe}, now,
	)
	if err == nil {
		t.Fatal("expected enc_secret_pairing CHECK violation, got nil error")
	}
	if !strings.Contains(err.Error(), "enc_secret_pairing") {
		t.Errorf("expected error mentioning enc_secret_pairing, got: %v", err)
	}
}
