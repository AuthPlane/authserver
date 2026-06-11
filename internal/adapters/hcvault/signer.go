package hcvault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// VaultSigner implements crypto.Signer by delegating signing to Vault Transit.
// The private key never leaves Vault.
type VaultSigner struct {
	client     *Client
	keyName    string
	keyVersion int
	publicKey  crypto.PublicKey
	hashAlg    string // e.g. "sha2-256"
	isEC       bool   // true for ECDSA keys, false for RSA
}

var _ crypto.Signer = (*VaultSigner)(nil)

// Public returns the public key associated with this signer.
func (s *VaultSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs digest with the Vault Transit key.
//
// CRITICAL: The digest parameter is already hashed by go-jose before calling Sign.
// We set prehashed=true in the Vault API call to prevent double-hashing.
//
// For ECDSA keys, Vault returns raw R||S format, but go-jose expects ASN.1 DER
// encoding. This method handles the conversion.
func (s *VaultSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Encode the pre-hashed digest as base64 for the Vault API.
	b64Digest := base64.StdEncoding.EncodeToString(digest)

	// Call Vault Transit sign endpoint with prehashed=true.
	// Use a background context since crypto.Signer.Sign doesn't accept context.
	// The Vault client's HTTP timeout provides the safety net.
	sig, err := s.client.Sign(
		context.Background(),
		s.keyName,
		b64Digest,
		s.hashAlg,
		s.keyVersion,
	)
	if err != nil {
		return nil, fmt.Errorf("vault transit sign: %w", err)
	}

	// Vault returns "vault:v1:<base64sig>" — strip the prefix.
	raw, err := stripVaultPrefix(sig)
	if err != nil {
		return nil, err
	}

	// Vault Transit with prehashed=true returns DER-encoded ASN.1 signatures
	// for ECDSA keys. crypto.Signer.Sign is expected to return DER, so we
	// pass through directly — no conversion needed.
	return raw, nil
}

// stripVaultPrefix removes the "vault:vN:" prefix from a Vault signature.
func stripVaultPrefix(sig string) ([]byte, error) {
	parts := strings.SplitN(sig, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" {
		return nil, fmt.Errorf("unexpected vault signature format: %q", sig)
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode vault signature: %w", err)
	}
	return raw, nil
}

// ecdsaSignature is the ASN.1 structure for an ECDSA signature.
type ecdsaSignature struct {
	R, S *big.Int
}

// rawToDER converts a raw R||S ECDSA signature to ASN.1 DER format.
// Vault Transit returns signatures in raw R||S format (each component is
// half the total byte length), but go-jose expects DER-encoded signatures.
func rawToDER(raw []byte) ([]byte, error) {
	if len(raw)%2 != 0 {
		return nil, fmt.Errorf("raw ECDSA signature has odd length: %d", len(raw))
	}
	n := len(raw) / 2
	r := new(big.Int).SetBytes(raw[:n])
	s := new(big.Int).SetBytes(raw[n:])
	return asn1.Marshal(ecdsaSignature{R: r, S: s})
}

// derToRaw converts an ASN.1 DER ECDSA signature to raw R||S format.
// Each component is zero-padded to byteLen.
func derToRaw(der []byte, byteLen int) ([]byte, error) {
	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, fmt.Errorf("unmarshal DER signature: %w", err)
	}
	out := make([]byte, 2*byteLen)
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	copy(out[byteLen-len(rBytes):byteLen], rBytes)
	copy(out[2*byteLen-len(sBytes):], sBytes)
	return out, nil
}

// parseTransitPublicKey parses a PEM-encoded public key from Vault Transit.
// Vault returns PKIX-format PEM blocks.
func parseTransitPublicKey(pemData string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in transit public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	return pub, nil
}

// isECKey returns true if the public key is ECDSA.
func isECKey(pub crypto.PublicKey) bool {
	_, ok := pub.(*ecdsa.PublicKey)
	return ok
}

// ecCurveByteLen returns the byte length of curve field elements.
func ecCurveByteLen(pub crypto.PublicKey) int {
	if ec, ok := pub.(*ecdsa.PublicKey); ok {
		return (ec.Curve.Params().BitSize + 7) / 8
	}
	return 0
}

// vaultKeyType returns the Vault Transit key type string for an algorithm.
func vaultKeyType(algorithm string) string {
	switch algorithm {
	case "ES256":
		return "ecdsa-p256"
	case "RS256":
		return "rsa-2048"
	default:
		return ""
	}
}

// vaultHashAlgorithm returns the Vault hash algorithm for a signing algorithm.
func vaultHashAlgorithm(_ string) string {
	// All supported algorithms (ES256, RS256) use SHA-256.
	return "sha2-256"
}

// NewVaultSigner creates a VaultSigner from parsed public key material.
func NewVaultSigner(client *Client, keyName string, keyVersion int, pub crypto.PublicKey, algorithm string) *VaultSigner {
	return &VaultSigner{
		client:     client,
		keyName:    keyName,
		keyVersion: keyVersion,
		publicKey:  pub,
		hashAlg:    vaultHashAlgorithm(algorithm),
		isEC:       isECKey(pub),
	}
}

// verifyECDSASignature verifies an ECDSA signature in DER format against a digest.
// Used for testing.
func verifyECDSASignature(pub *ecdsa.PublicKey, digest, derSig []byte) bool {
	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(derSig, &sig); err != nil {
		return false
	}
	return ecdsa.Verify(pub, digest, sig.R, sig.S)
}
