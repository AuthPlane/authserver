package hcvault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
)

func TestStripVaultPrefix(t *testing.T) {
	// Encode some test data as base64.
	raw := []byte("hello world")
	b64 := base64.StdEncoding.EncodeToString(raw)

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid v1", "vault:v1:" + b64, false},
		{"valid v2", "vault:v2:" + b64, false},
		{"invalid prefix", "notVault:v1:" + b64, true},
		{"missing parts", "vault:" + b64, true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := stripVaultPrefix(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != string(raw) {
				t.Errorf("got %q, want %q", got, raw)
			}
		})
	}
}

func TestRawToDER_RoundTrip(t *testing.T) {
	// Create known R and S values.
	r := big.NewInt(12345678901234567)
	s := big.NewInt(98765432109876543)
	byteLen := 32 // P-256

	// Build raw R||S.
	raw := make([]byte, 2*byteLen)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(raw[byteLen-len(rBytes):byteLen], rBytes)
	copy(raw[2*byteLen-len(sBytes):], sBytes)

	// Convert to DER.
	der, err := rawToDER(raw)
	if err != nil {
		t.Fatalf("rawToDER: %v", err)
	}

	// Parse DER to verify.
	var sig ecdsaSignature
	if _, unmarshalErr := asn1.Unmarshal(der, &sig); unmarshalErr != nil {
		t.Fatalf("unmarshal DER: %v", unmarshalErr)
	}
	if sig.R.Cmp(r) != 0 {
		t.Errorf("R = %v, want %v", sig.R, r)
	}
	if sig.S.Cmp(s) != 0 {
		t.Errorf("S = %v, want %v", sig.S, s)
	}

	// Convert back to raw.
	rawBack, err := derToRaw(der, byteLen)
	if err != nil {
		t.Fatalf("derToRaw: %v", err)
	}
	if len(rawBack) != len(raw) {
		t.Fatalf("rawBack len = %d, want %d", len(rawBack), len(raw))
	}
	for i := range raw {
		if raw[i] != rawBack[i] {
			t.Errorf("byte %d: got %d, want %d", i, rawBack[i], raw[i])
		}
	}
}

func TestRawToDER_OddLength(t *testing.T) {
	_, err := rawToDER(make([]byte, 63))
	if err == nil {
		t.Error("expected error for odd-length input")
	}
}

func TestRawToDER_RealECDSA(t *testing.T) {
	// Generate a real ECDSA key and sign data.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	digest := sha256.Sum256([]byte("test data"))

	// Sign with stdlib (produces DER).
	derSig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Parse DER to get R, S.
	var sig ecdsaSignature
	if _, unmarshalErr := asn1.Unmarshal(derSig, &sig); unmarshalErr != nil {
		t.Fatalf("unmarshal DER: %v", unmarshalErr)
	}

	// Convert to raw R||S format (simulating what Vault returns).
	byteLen := 32
	raw := make([]byte, 2*byteLen)
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	copy(raw[byteLen-len(rBytes):byteLen], rBytes)
	copy(raw[2*byteLen-len(sBytes):], sBytes)

	// Convert back to DER.
	derBack, err := rawToDER(raw)
	if err != nil {
		t.Fatalf("rawToDER: %v", err)
	}

	// Verify with the public key.
	if !verifyECDSASignature(&priv.PublicKey, digest[:], derBack) {
		t.Error("signature verification failed after round-trip")
	}
}

func TestParseTransitPublicKey_ECDSA(t *testing.T) {
	// Generate a test key and export its PKIX PEM.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pemData := testMarshalPKIXPEM(t, &priv.PublicKey)
	pub, err := parseTransitPublicKey(pemData)
	if err != nil {
		t.Fatalf("parseTransitPublicKey: %v", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
	if !ecPub.Equal(&priv.PublicKey) {
		t.Error("parsed public key doesn't match original")
	}
}

func TestParseTransitPublicKey_Invalid(t *testing.T) {
	_, err := parseTransitPublicKey("not valid PEM")
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestIsECKey(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if !isECKey(&priv.PublicKey) {
		t.Error("expected true for ECDSA key")
	}
}

func TestVaultKeyType(t *testing.T) {
	if vaultKeyType("ES256") != "ecdsa-p256" {
		t.Error("ES256 should map to ecdsa-p256")
	}
	if vaultKeyType("RS256") != "rsa-2048" {
		t.Error("RS256 should map to rsa-2048")
	}
	if vaultKeyType("unknown") != "" {
		t.Error("unknown should return empty string")
	}
}

func TestVaultHashAlgorithm(t *testing.T) {
	if vaultHashAlgorithm("ES256") != "sha2-256" {
		t.Error("ES256 should use sha2-256")
	}
	if vaultHashAlgorithm("RS256") != "sha2-256" {
		t.Error("RS256 should use sha2-256")
	}
}

func TestECCurveByteLen(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if ecCurveByteLen(&priv.PublicKey) != 32 {
		t.Errorf("expected 32 for P-256, got %d", ecCurveByteLen(&priv.PublicKey))
	}
}

// testMarshalPKIXPEM marshals a public key to PKIX PEM format for testing.
func testMarshalPKIXPEM(t *testing.T, pub interface{}) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal PKIX public key: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}
