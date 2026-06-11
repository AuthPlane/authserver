package crypto

import (
	"strings"
	"testing"
)

func TestClientSecret_HMAC_RoundTrip(t *testing.T) {
	SetClientSecretPepper("test-pepper-0123456789abcdef0123456789abcdef")
	t.Cleanup(func() { SetClientSecretPepper("") })

	secret := GenerateClientSecret()
	hash, err := HashClientSecret(secret)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(hash, clientSecretScheme) {
		t.Fatalf("expected HMAC scheme prefix, got %q", hash)
	}
	if err := CompareClientSecret(hash, secret); err != nil {
		t.Fatalf("correct secret should verify: %v", err)
	}
	if err := CompareClientSecret(hash, secret+"x"); err == nil {
		t.Fatal("wrong secret must not verify")
	}
}

func TestClientSecret_BcryptFallback_NoPepper(t *testing.T) {
	SetClientSecretPepper("") // explicit: no pepper

	hash, err := HashClientSecret("s3cr3t")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Fatalf("no pepper should fall back to bcrypt, got %q", hash)
	}
	if err := CompareClientSecret(hash, "s3cr3t"); err != nil {
		t.Fatalf("bcrypt secret should verify: %v", err)
	}
	if err := CompareClientSecret(hash, "wrong"); err == nil {
		t.Fatal("wrong secret must not verify")
	}
}

func TestClientSecret_BcryptBackCompat_WithPepper(t *testing.T) {
	// A legacy bcrypt-hashed client secret must still verify after a deployment
	// switches the pepper on.
	legacy, err := HashBcrypt("legacy-secret")
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}
	SetClientSecretPepper("now-there-is-a-pepper-aaaaaaaaaaaaaaaaaaaa")
	t.Cleanup(func() { SetClientSecretPepper("") })

	if err := CompareClientSecret(legacy, "legacy-secret"); err != nil {
		t.Fatalf("legacy bcrypt secret should still verify with pepper set: %v", err)
	}
}

func TestClientSecret_HMACHash_NoPepper_FailsClosed(t *testing.T) {
	SetClientSecretPepper("temp-pepper-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	hash, _ := HashClientSecret("s")
	SetClientSecretPepper("") // pepper lost/unset

	if err := CompareClientSecret(hash, "s"); err == nil {
		t.Fatal("an HMAC hash must not verify when no pepper is configured")
	}
}

func TestClientSecret_DifferentPepper_DoesNotVerify(t *testing.T) {
	SetClientSecretPepper("pepper-A-cccccccccccccccccccccccccccccccc")
	hash, _ := HashClientSecret("shared-secret")
	SetClientSecretPepper("pepper-B-dddddddddddddddddddddddddddddddd")
	t.Cleanup(func() { SetClientSecretPepper("") })

	if err := CompareClientSecret(hash, "shared-secret"); err == nil {
		t.Fatal("a hash made with a different pepper must not verify")
	}
}
