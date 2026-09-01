//go:build integration

package sqlite_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/testdata"
)

func TestBrokerGrantStore(t *testing.T) {
	testdata.RunBrokerGrantStoreTests(t, func(t *testing.T) testdata.BrokerGrantStoreSuiteDeps {
		stores := testdata.SetupTestStores(t)
		return testdata.BrokerGrantStoreSuiteDeps{
			Grants:    stores.BrokerGrant,
			Providers: stores.BrokerProvider,
			Users:     stores.User,
		}
	})
}

// TestBrokerGrantStore_CredentialData_StoredByteForByte verifies the contract
// documented in internal/ports/output/broker_grant_store.go: the adapter
// round-trips credential_data byte-for-byte without any transformation
// (no JSON wrapping, hex-encoding, compression, etc.). The
// BrokerIssuer relies on this contract — it encrypts plaintext with the
// DataEncryptor and stores the resulting ciphertext via this adapter; if
// the adapter silently transformed the bytes, decryption would fail at
// vend time, or worse, the bytes-on-disk shape would diverge from what
// the encryptor produced.
//
// Reads the raw row via the underlying *sql.DB to assert ciphertext-on-
// disk shape (the audit's HIGH-4 "encryption-on-disk assertion" gap, with
// the encryption itself being  BrokerIssuer's responsibility).
func TestBrokerGrantStore_CredentialData_StoredByteForByte(t *testing.T) {
	db := testdata.SetupTestDB(t)
	stores := db.NewStores()
	ctx := context.Background()

	// Seed FK targets directly via the stores. Minimal valid user +
	// broker_provider rows so the BrokerGrant FK chain is satisfiable.
	now := time.Now().UTC().Truncate(time.Second)
	if err := stores.User.Create(ctx, &user.User{
		ID: "u-bytes", Email: "bytes@example.com", Name: "Bytes",
		PasswordHash: "$2a$10$fakehash", Role: user.RoleUser,
		Status: user.StatusActive, Provider: user.ProviderLocal,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := stores.BrokerProvider.Create(ctx, &resource.BrokerProvider{
		ID: "p-bytes", Slug: "bytes-provider", DisplayName: "Bytes Provider",
		Protocol:   resource.ProtocolOAuth,
		ConfigData: []byte(`{"client_id":"x"}`),
		CreatedAt:  now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed broker_provider: %v", err)
	}

	// A distinctive byte sequence that would visibly mangle if the
	// adapter accidentally JSON-encoded, base64-wrapped, or compressed it.
	// Mix of high bits, nulls, and control bytes — invalid UTF-8, invalid
	// JSON, won't compress to itself.
	want := []byte{0x00, 0xFF, 0xC0, 0x80, 0x1B, 0x7F, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02}

	g := &resource.BrokerGrant{
		ID:               "bg-bytes",
		UserID:           "u-bytes",
		BrokerProviderID: "p-bytes",
		CredentialData:   want,
		ScopesGranted:    []string{"https://example.com/scope"},
		EncBackend:       "master-key",
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := stores.BrokerGrant.Create(ctx, g); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Bypass the adapter: read the column directly via *sql.DB.
	var got []byte
	if err := db.DB.QueryRowContext(ctx,
		`SELECT credential_data FROM broker_grants WHERE id = ?`, "bg-bytes",
	).Scan(&got); err != nil {
		t.Fatalf("raw SELECT: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("on-disk credential_data not byte-for-byte equal to input.\n got %x\nwant %x",
			got, want)
	}

	// Also verify Update preserves byte-for-byte transparency.
	rotated := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0xC2, 0xA9}
	g.CredentialData = rotated
	if err := stores.BrokerGrant.UpdateWithVersion(ctx, g); err != nil {
		t.Fatalf("UpdateWithVersion: %v", err)
	}
	if err := db.DB.QueryRowContext(ctx,
		`SELECT credential_data FROM broker_grants WHERE id = ?`, "bg-bytes",
	).Scan(&got); err != nil {
		t.Fatalf("raw SELECT after update: %v", err)
	}
	if !bytes.Equal(got, rotated) {
		t.Errorf("on-disk credential_data after UpdateWithVersion not byte-for-byte.\n got %x\nwant %x",
			got, rotated)
	}
}
