package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/testdata"
)

func TestRevocationStore(t *testing.T) {
	testdata.RunRevocationStoreTests(t, func(t *testing.T) (output.RevocationStore, output.TokenStore, output.ClientStore, output.UserStore) {
		s := testdata.SetupTestStores(t)
		return s.Revocation, s.Token, s.Client, s.User
	})
}

// SQLite stores expiries as RFC3339Nano text, which does not sort as time when
// fractional parts differ in length ("…:00Z" sorts after "…:00.5Z"). Revoking
// again must still keep the later instant.
func TestRevocationStore_RevokeJTI_KeepsLaterExpiry_SubSecond(t *testing.T) {
	db := testdata.SetupTestDB(t)
	rev := db.NewStores().Revocation
	ctx := context.Background()

	whole := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	later := whole.Add(500 * time.Millisecond)
	for _, exp := range []time.Time{whole, later, whole} {
		if err := rev.RevokeJTI(ctx, "jti-subsec", exp); err != nil {
			t.Fatalf("revoke until %s: %v", exp.Format(time.RFC3339Nano), err)
		}
	}

	var raw string
	if err := db.DB.QueryRowContext(ctx, `SELECT expires_at FROM revoked_jtis WHERE jti = ?`, "jti-subsec").Scan(&raw); err != nil {
		t.Fatalf("read row: %v", err)
	}
	got, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	if !got.Equal(later) {
		t.Errorf("stored expiry %s; want the later %s", raw, later.Format(time.RFC3339Nano))
	}
}
