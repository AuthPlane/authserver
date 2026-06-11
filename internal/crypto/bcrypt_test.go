package crypto

import "testing"

func TestHashBcrypt(t *testing.T) {
	hash, err := HashBcrypt("my-secret")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if hash == "" {
		t.Fatal("hash is empty")
	}
	if hash == "my-secret" {
		t.Fatal("hash equals plaintext")
	}
}

func TestCompareBcryptValid(t *testing.T) {
	hash, err := HashBcrypt("my-secret")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := CompareBcrypt(hash, "my-secret"); err != nil {
		t.Errorf("compare valid: %v", err)
	}
}

func TestCompareBcryptInvalid(t *testing.T) {
	hash, err := HashBcrypt("my-secret")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := CompareBcrypt(hash, "wrong-secret"); err == nil {
		t.Error("expected error for wrong secret")
	}
}

func TestHashBcryptDifferentResults(t *testing.T) {
	h1, _ := HashBcrypt("same")
	h2, _ := HashBcrypt("same")
	if h1 == h2 {
		t.Error("two hashes of same input should differ (different salts)")
	}
}
