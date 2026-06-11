//go:build integration

package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/adapters/sqlite"
	"github.com/authplane/authserver/testdata"
)

func TestResourceStore(t *testing.T) {
	testdata.RunResourceStoreTests(t, func(t *testing.T) testdata.ResourceStoreSuiteDeps {
		db := testdata.SetupTestDB(t)
		stores := db.NewStores()
		return testdata.ResourceStoreSuiteDeps{
			Resources:        stores.Resource,
			Providers:        stores.BrokerProvider,
			Users:            stores.User,
			Clients:          stores.Client,
			SeedConsentGrant: sqliteSeedConsentGrant(t, db),
			SeedIssuance:     sqliteSeedIssuance(t, db),
			SeedBrokerGrant:  sqliteSeedBrokerGrant(t, db),
		}
	})
}

func sqliteSeedConsentGrant(t *testing.T, db *sqlite.DB) func(t *testing.T, id, userID, clientID, resourceID string) {
	return func(t *testing.T, id, userID, clientID, resourceID string) {
		t.Helper()
		now := time.Now().UTC().Format(time.RFC3339Nano)
		_, err := db.DB.ExecContext(context.Background(),
			`INSERT INTO consent_grants
			 (id, user_id, client_id, resource_id, scopes, created_at, updated_at)
			 VALUES (?, ?, ?, ?, '[]', ?, ?)`,
			id, userID, clientID, resourceID, now, now)
		if err != nil {
			t.Fatalf("seed consent_grants: %v", err)
		}
	}
}

func sqliteSeedIssuance(t *testing.T, db *sqlite.DB) func(t *testing.T, id, userID, clientID, resourceID string) {
	return func(t *testing.T, id, userID, clientID, resourceID string) {
		t.Helper()
		now := time.Now().UTC()
		_, err := db.DB.ExecContext(context.Background(),
			`INSERT INTO issuances
			 (id, subject_user_id, client_id, resource_id, scopes, backend_kind,
			  revocable, issued_at, expires_at, agent_chain)
			 VALUES (?, ?, ?, ?, '[]', 'mint', 1, ?, ?, '[]')`,
			id, userID, clientID, resourceID,
			now.Format(time.RFC3339Nano),
			now.Add(time.Hour).Format(time.RFC3339Nano),
		)
		if err != nil {
			t.Fatalf("seed issuance: %v", err)
		}
	}
}

func sqliteSeedBrokerGrant(t *testing.T, db *sqlite.DB) func(t *testing.T, id, userID, providerID string) {
	return func(t *testing.T, id, userID, providerID string) {
		t.Helper()
		now := time.Now().UTC().Format(time.RFC3339Nano)
		_, err := db.DB.ExecContext(context.Background(),
			`INSERT INTO broker_grants
			 (id, user_id, broker_provider_id, credential_data, scopes_granted,
			  enc_backend, version, created_at, updated_at)
			 VALUES (?, ?, ?, ?, '[]', 'master-key', 1, ?, ?)`,
			id, userID, providerID, []byte("opaque"), now, now,
		)
		if err != nil {
			t.Fatalf("seed broker_grant: %v", err)
		}
	}
}
