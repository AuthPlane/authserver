package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Claim validation in this package fails closed: a required claim that is
// absent is a rejection, never a check that is skipped. Because the claim
// structs use value types, an absent JSON field and a literal zero decode to
// the same Go value, so presence and validity must be two separate checks —
// `if c.Expiry == 0 { reject }` before any comparison against the clock, never
// a single `c.Expiry != 0 && ...` guard, which silently turns a required claim
// into an optional one. Guard on zero only where the spec makes the claim
// genuinely optional (nbf), and say so in a comment. Any validator added here
// follows the same rule — see ValidateIDJAG in assertion.go for the shape.

// KeyPair holds a signing key and its metadata.
type KeyPair struct {
	PrivateKey crypto.Signer
	PublicKey  crypto.PublicKey
	Algorithm  jose.SignatureAlgorithm
	KeyID      string
}

// GenerateKeyPair generates an ECDSA or RSA key pair for the given algorithm.
// Supported: ES256 (P-256), RS256 (RSA 2048).
func GenerateKeyPair(alg, kid string) (*KeyPair, error) {
	kp := &KeyPair{
		Algorithm: jose.SignatureAlgorithm(alg),
		KeyID:     kid,
	}

	switch alg {
	case "ES256":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate EC key: %w", err)
		}
		kp.PrivateKey = priv
		kp.PublicKey = &priv.PublicKey
	case "RS256":
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate RSA key: %w", err)
		}
		kp.PrivateKey = priv
		kp.PublicKey = &priv.PublicKey
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}

	return kp, nil
}

// AccessTokenClaims are the claims in an RFC 9068 JWT access token.
// Audience is []string for JSON marshal flexibility. Per RFC 8707 we bind
// each token to a single resource, so Audience will have exactly one element.
// JSON serializes as ["https://..."] (array), which is valid per RFC 7519 §4.1.3.
type AccessTokenClaims struct {
	Issuer     string                 `json:"iss"`
	Subject    string                 `json:"sub"`
	Audience   []string               `json:"aud"`
	ClientID   string                 `json:"client_id"`
	Scope      string                 `json:"scope,omitempty"`
	JTI        string                 `json:"jti"`
	IssuedAt   int64                  `json:"iat"`
	Expiry     int64                  `json:"exp"`
	NotBefore  int64                  `json:"nbf"`
	Cnf        map[string]interface{} `json:"cnf,omitempty"`         // DPoP confirmation claim (RFC 9449 §6): {"jkt": "<thumbprint>"}
	Act        map[string]interface{} `json:"act,omitempty"`         // RFC 8693 §4.1: delegation chain {"sub": "...", "act": {...}}
	MayAct     map[string]interface{} `json:"may_act,omitempty"`     // RFC 8693 §5: authorized actors {"sub": "..."}
	AgentID    string                 `json:"agent_id,omitempty"`    // Authplane extension: client_id of the acting agent
	AgentChain []string               `json:"agent_chain,omitempty"` // Authplane extension: ordered delegation chain [root, ..., acting_agent]
}

// HasAudience returns true if the given value is present in the Audience slice.
func (c *AccessTokenClaims) HasAudience(aud string) bool {
	for _, a := range c.Audience {
		if a == aud {
			return true
		}
	}
	return false
}

// ValidateAccessTokenClaims checks that required JWT claims are non-empty before signing.
func ValidateAccessTokenClaims(c AccessTokenClaims) error {
	if c.Issuer == "" {
		return fmt.Errorf("iss claim is required")
	}
	if c.Subject == "" {
		return fmt.Errorf("sub claim is required")
	}
	if len(c.Audience) == 0 || c.Audience[0] == "" {
		return fmt.Errorf("aud claim is required")
	}
	if c.ClientID == "" {
		return fmt.Errorf("client_id claim is required")
	}
	if c.JTI == "" {
		return fmt.Errorf("jti claim is required")
	}
	if c.Expiry == 0 {
		return fmt.Errorf("exp claim is required")
	}
	// iat is REQUIRED for at+jwt (RFC 9068 §2.2) and VerifyAccessToken rejects
	// its absence, so the gate must refuse it here too. Otherwise this server
	// can sign a token it will reject on every subsequent use, and the failure
	// surfaces far from the mint path that caused it.
	if c.IssuedAt == 0 {
		return fmt.Errorf("iat claim is required")
	}
	return nil
}

// SignAccessToken signs an RFC 9068 JWT access token with typ: at+jwt.
// Returns an error if required claims are missing.
//
// For concrete key types (*ecdsa.PrivateKey, *rsa.PrivateKey) the key is
// passed directly to go-jose. For opaque crypto.Signer implementations
// (e.g. Vault Transit, KMS) the key is wrapped as a jose.OpaqueSigner
// so go-jose delegates signing without needing access to raw key material.
func SignAccessToken(kp *KeyPair, claims AccessTokenClaims) (string, error) {
	if err := ValidateAccessTokenClaims(claims); err != nil {
		return "", fmt.Errorf("invalid claims: %w", err)
	}

	// Determine the signing key for go-jose. Concrete private key types
	// are passed directly; opaque signers (KMS, HSM, Vault) are wrapped
	// via jose.OpaqueSigner so go-jose calls SignPayload instead of
	// accessing raw key bytes.
	var key interface{}
	switch kp.PrivateKey.(type) {
	case *ecdsa.PrivateKey, *rsa.PrivateKey:
		key = kp.PrivateKey
	default:
		key = &opaqueCryptoSigner{
			signer: kp.PrivateKey,
			kid:    kp.KeyID,
			alg:    kp.Algorithm,
		}
	}

	signingKey := jose.SigningKey{
		Algorithm: kp.Algorithm,
		Key:       key,
	}
	opts := &jose.SignerOptions{}
	opts.WithType("at+jwt")
	opts.WithHeader(jose.HeaderKey("kid"), kp.KeyID)

	signer, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		return "", fmt.Errorf("create signer: %w", err)
	}

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return raw, nil
}

// opaqueCryptoSigner adapts a crypto.Signer to jose.OpaqueSigner.
// This allows remote signing backends (Vault Transit, cloud KMS) to work
// with go-jose, which requires either concrete key types or OpaqueSigner.
type opaqueCryptoSigner struct {
	signer crypto.Signer
	kid    string
	alg    jose.SignatureAlgorithm
}

// Public returns the public JWK for this signer, including key ID and algorithm.
func (o *opaqueCryptoSigner) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{
		Key:       o.signer.Public(),
		KeyID:     o.kid,
		Algorithm: string(o.alg),
		Use:       "sig",
	}
}

// Algs returns the signature algorithms supported by this signer.
func (o *opaqueCryptoSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{o.alg}
}

// SignPayload hashes the payload and signs it using the underlying crypto.Signer.
func (o *opaqueCryptoSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	// go-jose calls SignPayload with the raw payload. We need to hash it
	// before passing to crypto.Signer.Sign, which expects a pre-hashed digest.
	var hash crypto.Hash
	switch alg {
	case jose.ES256, jose.RS256, jose.PS256:
		hash = crypto.SHA256
	case jose.ES384, jose.RS384, jose.PS384:
		hash = crypto.SHA384
	case jose.ES512, jose.RS512, jose.PS512:
		hash = crypto.SHA512
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}

	hasher := hash.New()
	hasher.Write(payload)
	digest := hasher.Sum(nil)

	sig, err := o.signer.Sign(rand.Reader, digest, hash)
	if err != nil {
		return nil, err
	}

	// crypto.Signer.Sign returns DER-encoded ECDSA signatures, but
	// jose.OpaqueSigner.SignPayload must return raw R||S (the JWS wire format).
	// Convert DER → raw R||S for EC algorithms.
	switch alg {
	case jose.ES256, jose.ES384, jose.ES512:
		return ecDERToRaw(sig, alg)
	default:
		return sig, nil
	}
}

// ecDERToRaw converts a DER-encoded ECDSA signature to the raw R||S format
// that JWS uses. Each component is zero-padded to the curve's byte length.
func ecDERToRaw(der []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	var byteLen int
	switch alg {
	case jose.ES256:
		byteLen = 32
	case jose.ES384:
		byteLen = 48
	case jose.ES512:
		byteLen = 66
	default:
		return nil, fmt.Errorf("not an EC algorithm: %s", alg)
	}

	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, fmt.Errorf("unmarshal DER ECDSA signature: %w", err)
	}

	out := make([]byte, 2*byteLen)
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	copy(out[byteLen-len(rBytes):byteLen], rBytes)
	copy(out[2*byteLen-len(sBytes):], sBytes)
	return out, nil
}

// VerifyAccessToken parses and verifies a JWT access token against the given JWKS.
// It checks the signature, the typ header, the presence of exp and iat, and the
// expiry and not-before windows. RFC 9068 §2.2 also makes iss, sub, aud,
// client_id and jti REQUIRED; those are gated at issuance by
// ValidateAccessTokenClaims rather than re-checked here.
func VerifyAccessToken(token string, jwks *jose.JSONWebKeySet) (*AccessTokenClaims, error) {
	parsed, err := jwt.ParseSigned(token, supportedAlgorithms())
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	// Verify typ header
	if len(parsed.Headers) == 0 {
		return nil, fmt.Errorf("missing token headers")
	}
	typ, _ := parsed.Headers[0].ExtraHeaders[jose.HeaderType].(string)
	if typ != "at+jwt" {
		return nil, fmt.Errorf("invalid typ header: expected at+jwt, got %q", typ)
	}

	// Find signing key by kid
	kid := parsed.Headers[0].KeyID
	keys := jwks.Key(kid)
	if len(keys) == 0 {
		return nil, fmt.Errorf("unknown key id: %s", kid)
	}

	var claims AccessTokenClaims
	if err := parsed.Claims(keys[0].Key, &claims); err != nil {
		return nil, fmt.Errorf("verify claims: %w", err)
	}

	now := time.Now().Unix()
	const clockSkew int64 = 30

	// Check expiry (30-second clock skew tolerance). exp is REQUIRED for
	// at+jwt (RFC 9068 §2.2), so a missing one is rejected rather than
	// treated as "no expiry to enforce" — see the fail-closed note above.
	if claims.Expiry == 0 {
		return nil, fmt.Errorf("missing exp claim")
	}
	if now > claims.Expiry+clockSkew {
		return nil, fmt.Errorf("token expired")
	}

	// iat is REQUIRED for at+jwt (RFC 9068 §2.2) exactly as exp is, so its
	// absence is a rejection under the same rule. Only presence is enforced
	// here: an iat in the future is a validity question the spec leaves to the
	// verifier, and ValidateAccessTokenClaims does not constrain it at issuance.
	if claims.IssuedAt == 0 {
		return nil, fmt.Errorf("missing iat claim")
	}

	// Check not-before (30-second clock skew tolerance). Unlike exp, nbf is
	// OPTIONAL (RFC 7519 §4.1.5) and RFC 9068 does not require it, so its
	// absence is a valid token, not a missing required claim: skipping the
	// check when it is zero is the correct semantics, not a permissive default.
	if claims.NotBefore != 0 && now < claims.NotBefore-clockSkew {
		return nil, fmt.Errorf("token not yet valid")
	}

	return &claims, nil
}

// VerifyAccessTokenWithIssuer is like VerifyAccessToken but also validates the issuer claim.
// CODE FIX: Matrix 1.5.16 — issuer MUST be verified to prevent cross-issuer token injection.
func VerifyAccessTokenWithIssuer(token string, jwks *jose.JSONWebKeySet, expectedIssuer string) (*AccessTokenClaims, error) {
	claims, err := VerifyAccessToken(token, jwks)
	if err != nil {
		return nil, err
	}
	if claims.Issuer != expectedIssuer {
		return nil, fmt.Errorf("invalid issuer: expected %q, got %q", expectedIssuer, claims.Issuer)
	}
	return claims, nil
}

// BuildJWKS constructs a jose.JSONWebKeySet from one or more key pairs.
func BuildJWKS(keys ...*KeyPair) jose.JSONWebKeySet {
	jwks := jose.JSONWebKeySet{}
	for _, kp := range keys {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:       kp.PublicKey,
			KeyID:     kp.KeyID,
			Algorithm: string(kp.Algorithm),
			Use:       "sig",
		})
	}
	return jwks
}

func supportedAlgorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.ES256, jose.RS256}
}
