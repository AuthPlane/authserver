//go:build integration

package sqlite_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/testdata"
)

// --- F3.5: SQL Injection Tests ---

// TestSQLInjection_ClientStore verifies parameterized queries prevent SQL injection
// in client store operations (create, get, list).
func TestSQLInjection_ClientStore(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	ctx := context.Background()

	maliciousNames := []string{
		"'; DROP TABLE clients; --",
		`" OR 1=1 --`,
		"admin' UNION SELECT * FROM users --",
		"test'; DELETE FROM clients WHERE '1'='1",
		"Robert'); DROP TABLE clients;--",
		"name/**/OR/**/1=1",
		"test\x00null_byte",
	}

	for i, name := range maliciousNames {
		t.Run(fmt.Sprintf("client_name_%d", i), func(t *testing.T) {
			c := &client.Client{
				ID:                      crypto.GenerateRandomString(16),
				Name:                    name,
				RedirectURIs:            []string{"https://example.com/callback"},
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
				TokenEndpointAuthMethod: "none",
				Status:                  client.StatusActive,
				RegistrationSource:      "dcr",
				IssuedAt:                time.Now().UTC(),
				UpdatedAt:               time.Now().UTC(),
			}

			if err := stores.Client.Create(ctx, c); err != nil {
				t.Fatalf("Create with malicious name should succeed: %v", err)
			}

			got, err := stores.Client.GetByID(ctx, c.ID)
			if err != nil {
				t.Fatalf("GetByID should succeed: %v", err)
			}

			if got.Name != name {
				t.Errorf("name mismatch: got %q, want %q", got.Name, name)
			}
		})
	}
}

// TestSQLInjection_UserStore verifies parameterized queries prevent SQL injection
// in user store operations.
func TestSQLInjection_UserStore(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	ctx := context.Background()

	maliciousEmails := []string{
		"'; DROP TABLE users; --@evil.com",
		`" OR 1=1 --@evil.com`,
		"admin' UNION SELECT * FROM users --@evil.com",
	}

	for i, email := range maliciousEmails {
		t.Run(fmt.Sprintf("email_%d", i), func(t *testing.T) {
			u := &user.User{
				ID:        crypto.GenerateRandomString(16),
				Email:     email,
				Name:      "Test User",
				Role:      user.RoleUser,
				Status:    user.StatusActive,
				Provider:  user.ProviderLocal,
				CreatedAt: time.Now().UTC(),
				UpdatedAt: time.Now().UTC(),
			}

			if err := stores.User.Create(ctx, u); err != nil {
				t.Fatalf("Create with malicious email should succeed: %v", err)
			}

			got, err := stores.User.GetByID(ctx, u.ID)
			if err != nil {
				t.Fatalf("GetByID should succeed: %v", err)
			}

			if got.Email != email {
				t.Errorf("email mismatch: got %q, want %q", got.Email, email)
			}
		})
	}
}

// --- F4.3: Concurrent Revocation Store Test ---

// TestRevocationStore_ConcurrentAccess verifies the revocation store is safe
// under concurrent access from multiple goroutines.
func TestRevocationStore_ConcurrentAccess(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	ctx := context.Background()

	testdata.SeedClientAndUser(t, stores.Client, stores.User, "client-concurrent", "user-concurrent")

	// Tracked JTIs must reference a real token family (FK constraint).
	if err := stores.Token.CreateFamily(ctx, &token.Family{
		ID:        "family-concurrent",
		ClientID:  "client-concurrent",
		UserID:    "user-concurrent",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create family: %v", err)
	}

	const numGoroutines = 10
	const opsPerGoroutine = 50

	var wg sync.WaitGroup
	errCh := make(chan error, numGoroutines*opsPerGoroutine)

	// Concurrent TrackJTI writes.
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				jti := fmt.Sprintf("jti-%d-%d", id, j)
				if err := stores.Revocation.TrackJTI(ctx, jti, "family-concurrent", time.Now().Add(time.Hour)); err != nil {
					errCh <- fmt.Errorf("TrackJTI(%s): %w", jti, err)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent TrackJTI failed: %v", err)
	}

	// Verify all JTIs are readable.
	for i := 0; i < numGoroutines; i++ {
		for j := 0; j < opsPerGoroutine; j++ {
			jti := fmt.Sprintf("jti-%d-%d", i, j)
			revoked, err := stores.Revocation.IsRevoked(ctx, jti)
			if err != nil {
				t.Fatalf("IsRevoked(%s): %v", jti, err)
			}
			if revoked {
				t.Errorf("JTI %s should not be revoked yet", jti)
			}
		}
	}

	// Concurrent revocation + reads.
	var wg2 sync.WaitGroup
	errCh2 := make(chan error, numGoroutines*2)

	// Writers: revoke by family.
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		if err := stores.Revocation.RevokeByFamily(ctx, "family-concurrent"); err != nil {
			errCh2 <- fmt.Errorf("RevokeByFamily: %w", err)
		}
	}()

	// Readers: check IsRevoked concurrently.
	for i := 0; i < numGoroutines; i++ {
		wg2.Add(1)
		go func(id int) {
			defer wg2.Done()
			jti := fmt.Sprintf("jti-%d-0", id)
			_, err := stores.Revocation.IsRevoked(ctx, jti)
			if err != nil {
				errCh2 <- fmt.Errorf("IsRevoked(%s): %w", jti, err)
			}
		}(i)
	}

	wg2.Wait()
	close(errCh2)

	for err := range errCh2 {
		t.Fatalf("concurrent revocation operation failed: %v", err)
	}
}

// --- F7: Unicode and Special Character Tests ---

// TestUnicode_ClientNames verifies that unicode client names round-trip correctly.
func TestUnicode_ClientNames(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	ctx := context.Background()

	unicodeNames := []string{
		"Café API Client",
		"中文客户端",
		"日本語クライアント",
		"한국어 클라이언트",
		"Client™ © 2026",
		"مرحبا بالعالم",
		"שלום עולם",
		"Ñoño's Tëst Clîent",
		"emoji 🔐🎯👤 client",
		"zero\u200Bwidth\u200Bjoin",
	}

	for _, name := range unicodeNames {
		t.Run(name, func(t *testing.T) {
			c := &client.Client{
				ID:                      crypto.GenerateRandomString(16),
				Name:                    name,
				RedirectURIs:            []string{"https://example.com/callback"},
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
				TokenEndpointAuthMethod: "none",
				Status:                  client.StatusActive,
				RegistrationSource:      "dcr",
				IssuedAt:                time.Now().UTC(),
				UpdatedAt:               time.Now().UTC(),
			}

			if err := stores.Client.Create(ctx, c); err != nil {
				t.Fatalf("Create: %v", err)
			}

			got, err := stores.Client.GetByID(ctx, c.ID)
			if err != nil {
				t.Fatalf("GetByID: %v", err)
			}

			if got.Name != name {
				t.Errorf("name mismatch: got %q, want %q", got.Name, name)
			}
		})
	}
}

// TestUnicode_UserEmails verifies that unicode user data round-trips correctly.
func TestUnicode_UserEmails(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	ctx := context.Background()

	testCases := []struct {
		email string
		name  string
	}{
		{"café@example.com", "Ñoño Test"},
		{"user@日本語.jp", "田中太郎"},
		{"사용자@한국어.kr", "홍길동"},
		{"user@مثال.com", "مستخدم"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u := &user.User{
				ID:        crypto.GenerateRandomString(16),
				Email:     tc.email,
				Name:      tc.name,
				Role:      user.RoleUser,
				Status:    user.StatusActive,
				Provider:  user.ProviderLocal,
				CreatedAt: time.Now().UTC(),
				UpdatedAt: time.Now().UTC(),
			}

			if err := stores.User.Create(ctx, u); err != nil {
				t.Fatalf("Create: %v", err)
			}

			got, err := stores.User.GetByID(ctx, u.ID)
			if err != nil {
				t.Fatalf("GetByID: %v", err)
			}

			if got.Email != tc.email {
				t.Errorf("email mismatch: got %q, want %q", got.Email, tc.email)
			}
			if got.Name != tc.name {
				t.Errorf("name mismatch: got %q, want %q", got.Name, tc.name)
			}
		})
	}
}
