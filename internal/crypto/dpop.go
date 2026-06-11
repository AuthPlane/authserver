package crypto

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/authplane/authserver/internal/domain"
)

// dpopSupportedAlgorithms lists the asymmetric algorithms accepted for DPoP proofs.
// Symmetric algorithms (HS*) and alg:none are rejected per RFC 9449 §4.3.
var dpopSupportedAlgorithms = []jose.SignatureAlgorithm{
	jose.ES256,
	jose.RS256,
	jose.PS256,
}

// dpopClaims are the payload claims of a DPoP proof JWT (RFC 9449 §4.2).
type dpopClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	ATH   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

// DPoPResult holds the validated output from a DPoP proof.
type DPoPResult struct {
	JKT   string // JWK thumbprint (base64url-encoded SHA-256)
	JTI   string // unique identifier from the proof, for replay detection
	Nonce string // nonce from the proof, if present
}

// ValidateProof validates a DPoP proof JWT per RFC 9449 §4.3.
//
// Parameters:
//   - proof: the raw DPoP proof JWT string from the DPoP header
//   - method: the HTTP method of the request (e.g. "POST")
//   - reqURL: the HTTP URL of the request (scheme + host + path; query is stripped)
//   - serverNonce: the expected server nonce (empty string if nonce is not required)
//   - accessTokenHash: base64url(SHA-256(access_token)) for ath validation (empty if not applicable)
//   - proofLifetime: maximum age of the proof (|now - iat| must be within this)
//
// Returns:
//   - DPoPResult with JKT, JTI, and Nonce on success
//   - domain.ErrDPoPInvalidProof on structural/cryptographic errors
//   - domain.ErrDPoPNonceRequired if serverNonce is non-empty but proof has no nonce
//   - domain.ErrDPoPNonceMismatch if proof nonce doesn't match serverNonce
func ValidateProof(proof, method, reqURL, serverNonce, accessTokenHash string, proofLifetime time.Duration) (*DPoPResult, error) {
	// Parse the JWT. This also rejects unsupported algorithms (alg:none, HS*).
	parsed, err := jwt.ParseSigned(proof, dpopSupportedAlgorithms)
	if err != nil {
		return nil, domain.ErrDPoPInvalidProof
	}

	// Exactly one header expected.
	if len(parsed.Headers) != 1 {
		return nil, domain.ErrDPoPInvalidProof
	}
	header := parsed.Headers[0]

	// Check typ: dpop+jwt (case-insensitive per RFC 9449 §4.2).
	typ, _ := header.ExtraHeaders[jose.HeaderType].(string)
	if !strings.EqualFold(typ, "dpop+jwt") {
		return nil, domain.ErrDPoPInvalidProof
	}

	// Extract the jwk header — must be present and be a public key.
	jwk, err := extractPublicJWK(header)
	if err != nil {
		return nil, domain.ErrDPoPInvalidProof
	}

	// Verify the signature using the embedded public key.
	var claims dpopClaims
	if claimsErr := parsed.Claims(jwk.Key, &claims); claimsErr != nil {
		return nil, domain.ErrDPoPInvalidProof
	}

	// Validate jti (required, non-empty).
	if claims.JTI == "" {
		return nil, domain.ErrDPoPInvalidProof
	}

	// Validate htm (HTTP method, case-insensitive comparison).
	if !strings.EqualFold(claims.HTM, method) {
		return nil, domain.ErrDPoPInvalidProof
	}

	// Validate htu (scheme + host + path; strip query and fragment before comparison).
	if htuErr := validateHTU(claims.HTU, reqURL); htuErr != nil {
		return nil, domain.ErrDPoPInvalidProof
	}

	// Validate iat freshness.
	if claims.IAT == 0 {
		return nil, domain.ErrDPoPInvalidProof
	}
	now := time.Now()
	iat := time.Unix(claims.IAT, 0)
	diff := now.Sub(iat)
	if diff < 0 {
		diff = -diff
	}
	if diff > proofLifetime {
		return nil, domain.ErrDPoPInvalidProof
	}

	// Validate nonce if server requires it.
	if serverNonce != "" {
		if claims.Nonce == "" {
			return nil, domain.ErrDPoPNonceRequired
		}
		if claims.Nonce != serverNonce {
			return nil, domain.ErrDPoPNonceMismatch
		}
	}

	// Validate ath (access token hash) if provided.
	if accessTokenHash != "" {
		if claims.ATH == "" || claims.ATH != accessTokenHash {
			return nil, domain.ErrDPoPInvalidProof
		}
	}

	// Compute JWK thumbprint.
	jkt, err := ComputeJKT(jwk)
	if err != nil {
		return nil, domain.ErrDPoPInvalidProof
	}

	return &DPoPResult{
		JKT:   jkt,
		JTI:   claims.JTI,
		Nonce: claims.Nonce,
	}, nil
}

// ComputeJKT computes the JWK Thumbprint per RFC 7638 using SHA-256.
// Returns the base64url-encoded (no padding) SHA-256 hash of the JWK's
// canonical form (sorted, minimal members as per the key type).
func ComputeJKT(jwk jose.JSONWebKey) (string, error) {
	thumbprint, err := jwk.Thumbprint(stdcrypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("compute JWK thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// GenerateNonce creates a cryptographically random nonce for DPoP.
// Returns a 32-byte base64url-encoded string (43 chars).
func GenerateNonce() string {
	return GenerateRandomString(32)
}

// ComputeATH computes the access token hash for DPoP ath claim.
// Returns base64url(SHA-256(access_token)).
func ComputeATH(accessToken string) string {
	h := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// IsDPoPBound checks if an access token has a cnf.jkt claim indicating DPoP binding.
// This is used to determine if a resource request requires a DPoP proof.
func IsDPoPBound(claims *AccessTokenClaims) bool {
	if claims == nil || claims.Cnf == nil {
		return false
	}
	_, ok := claims.Cnf["jkt"]
	return ok
}

// extractPublicJWK extracts the public JWK from the DPoP proof header.
// Returns an error if the key is absent, is a private key, or is not an
// asymmetric public key (EC or RSA).
func extractPublicJWK(header jose.Header) (jose.JSONWebKey, error) {
	// go-jose v4 parses the standard "jwk" header into header.JSONWebKey.
	// Fall back to ExtraHeaders for non-standard serialization.
	var jwk jose.JSONWebKey
	if header.JSONWebKey != nil {
		jwk = *header.JSONWebKey
	} else {
		// Try ExtraHeaders as fallback.
		raw, ok := header.ExtraHeaders["jwk"]
		if !ok {
			return jose.JSONWebKey{}, errors.New("missing jwk header")
		}
		rawBytes, err := json.Marshal(raw)
		if err != nil {
			return jose.JSONWebKey{}, fmt.Errorf("marshal jwk header: %w", err)
		}
		if err := jwk.UnmarshalJSON(rawBytes); err != nil {
			return jose.JSONWebKey{}, fmt.Errorf("unmarshal jwk: %w", err)
		}
	}

	// Reject private keys — DPoP proof must only contain the public key.
	if !jwk.IsPublic() {
		return jose.JSONWebKey{}, errors.New("jwk contains private key")
	}

	// Verify it's a supported key type.
	switch k := jwk.Key.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() && k.Curve != elliptic.P521() {
			return jose.JSONWebKey{}, errors.New("unsupported EC curve")
		}
	case *rsa.PublicKey:
		if k.Size() < 256 { // 2048 bits = 256 bytes
			return jose.JSONWebKey{}, errors.New("RSA key too small (minimum 2048 bits)")
		}
	default:
		return jose.JSONWebKey{}, errors.New("unsupported key type")
	}

	return jwk, nil
}

// validateHTU validates the htu claim by comparing scheme+host+path.
// Query string and fragment are stripped from both sides before comparison.
func validateHTU(htu, reqURL string) error {
	htuParsed, err := url.Parse(htu)
	if err != nil {
		return fmt.Errorf("parse htu: %w", err)
	}

	reqParsed, err := url.Parse(reqURL)
	if err != nil {
		return fmt.Errorf("parse request URL: %w", err)
	}

	// Compare scheme + host + path (case-insensitive scheme and host).
	if !strings.EqualFold(htuParsed.Scheme, reqParsed.Scheme) {
		return fmt.Errorf("scheme mismatch")
	}
	if !strings.EqualFold(htuParsed.Host, reqParsed.Host) {
		return fmt.Errorf("host mismatch")
	}
	if htuParsed.Path != reqParsed.Path {
		return fmt.Errorf("path mismatch")
	}

	return nil
}

// NewDPoPSigner creates a jose.Signer for DPoP proofs with the correct headers.
// Sets typ: dpop+jwt and embeds the public key in the jwk header.
func NewDPoPSigner(privateKey interface{}, alg jose.SignatureAlgorithm) (jose.Signer, error) {
	signingKey := jose.SigningKey{
		Algorithm: alg,
		Key:       privateKey,
	}
	opts := &jose.SignerOptions{}
	opts.WithType("dpop+jwt")

	// Embed the public key in the jwk header.
	var pubKey interface{}
	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	default:
		return nil, fmt.Errorf("unsupported key type for DPoP signer: %T", privateKey)
	}
	opts.WithHeader("jwk", jose.JSONWebKey{Key: pubKey})

	signer, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		return nil, fmt.Errorf("create DPoP signer: %w", err)
	}
	return signer, nil
}

// CreateDPoPProof creates a DPoP proof JWT. Used in tests and as a helper.
func CreateDPoPProof(signer jose.Signer, jti, htm, htu string, iat time.Time, nonce, ath string) (string, error) {
	claims := map[string]interface{}{
		"jti": jti,
		"htm": htm,
		"htu": htu,
		"iat": iat.Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if ath != "" {
		claims["ath"] = ath
	}

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("sign DPoP proof: %w", err)
	}
	return raw, nil
}
