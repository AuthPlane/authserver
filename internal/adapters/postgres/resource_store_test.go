//go:build integration_postgres

package postgres_test

import (
	"context"
	"testing"
	"time"

	pgadapter "github.com/authplane/authserver/internal/adapters/postgres"
	"github.com/authplane/authserver/testdata"
)

func TestResourceStore(t *testing.T) {
	testdata.RunResourceStoreTests(t, func(t *testing.T) testdata.ResourceStoreSuiteDeps {
		db := testdata.SetupTestPGDB(t, pgContainerDSN)
		stores := db.NewStores()
		return testdata.ResourceStoreSuiteDeps{
			Resources:        stores.Resource,
			Providers:        stores.BrokerProvider,
			Users:            stores.User,
			Clients:          stores.Client,
			SeedConsentGrant: pgSeedConsentGrant(t, db),
			SeedIssuance:     pgSeedIssuance(t, db),
			SeedBrokerGrant:  pgSeedBrokerGrant(t, db),
		}
	})
}

func pgSeedConsentGrant(t *testing.T, db *pgadapter.DB) func(t *testing.T, id, userID, clientID, resourceID string) {
	return func(t *testing.T, id, userID, clientID, resourceID string) {
		t.Helper()
		_, err := db.Pool.Exec(context.Background(),
			`INSERT INTO consent_grants
			 (id, user_id, client_id, resource_id, scopes, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, '{}'::text[], NOW(), NOW())`,
			id, userID, clientID, resourceID)
		if err != nil {
			t.Fatalf("seed consent_grants: %v", err)
		}
	}
}

func pgSeedIssuance(t *testing.T, db *pgadapter.DB) func(t *testing.T, id, userID, clientID, resourceID string) {
	return func(t *testing.T, id, userID, clientID, resourceID string) {
		t.Helper()
		_, err := db.Pool.Exec(context.Background(),
			`INSERT INTO issuances
			 (id, subject_user_id, client_id, resource_id, scopes, backend_kind,
			  revocable, expires_at)
			 VALUES ($1, $2, $3, $4, '{}'::text[], 'mint', true, NOW() + interval '1 hour')`,
			id, userID, clientID, resourceID)
		if err != nil {
			t.Fatalf("seed issuance: %v", err)
		}
	}
}

func pgSeedBrokerGrant(t *testing.T, db *pgadapter.DB) func(t *testing.T, id, userID, providerID string) {
	return func(t *testing.T, id, userID, providerID string) {
		t.Helper()
		_, err := db.Pool.Exec(context.Background(),
			`INSERT INTO broker_grants
			 (id, user_id, broker_provider_id, credential_data, scopes_granted,
			  enc_backend, version, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, '{}'::text[], 'master-key', 1, $5, $5)`,
			id, userID, providerID, []byte("opaque"), time.Now().UTC())
		if err != nil {
			t.Fatalf("seed broker_grant: %v", err)
		}
	}
}
