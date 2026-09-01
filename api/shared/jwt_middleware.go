package shared

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

const claimsKey contextKey = "jwtClaims"

// Error codes carried in the challenge and the response body. invalid_token is
// RFC 6750 §3.1; invalid_dpop_proof is RFC 9449 §7.1, and telling them apart is
// what lets a client know whether to fetch a new token or re-sign its proof.
const (
	errInvalidToken     = "invalid_token"      //nolint:gosec // G101: an RFC 6750 error code, not a credential
	errInvalidDPoPProof = "invalid_dpop_proof" // RFC 9449 §7.1
)

// maxDPoPProofJTILen bounds the DPoP proof jti accepted as a replay-store key.
// RFC 9449 does not fix a length; this is generous for any sane nonce and
// still refuses a caller-chosen key large enough to matter in a shared store.
const maxDPoPProofJTILen = 255

// ClaimsFromContext returns the validated JWT access token claims from the request context.
func ClaimsFromContext(ctx context.Context) (*crypto.AccessTokenClaims, bool) {
	c, ok := ctx.Value(claimsKey).(*crypto.AccessTokenClaims)
	return c, ok
}

// JWKSProvider provides the JWKS key set for JWT verification.
type JWKSProvider interface {
	BuildJWKS(ctx context.Context) (*jose.JSONWebKeySet, error)
}

// DPoPJWTConfig sets the DPoP proof-freshness window for the JWT middleware.
// It never enables or disables enforcement: a token carrying cnf.jkt is
// validated whatever this says, and so is any request using the DPoP
// authorization scheme.
//
// The zero value means the 60-second default, through
// [NewResourceJWTMiddleware] and [JWTMiddleware.WithDPoP] alike: both ignore a
// non-positive ProofLifetime rather than storing it. They have to agree — a
// zero window stored verbatim rejects every proof while the challenge still
// advertises DPoP, and the same value meaning opposite things across two
// public entry points is the trap this type's documentation once set.
type DPoPJWTConfig struct {
	ProofLifetime time.Duration // max |now - iat| for proof freshness
}

// DPoPProofStore records consumed DPoP proof JTIs for replay detection at the
// resource server. Mirrors output.DPoPNonceStore.ConsumeJTI so the existing
// SQLite/Postgres adapters can be passed in by the composition root.
type DPoPProofStore interface {
	ConsumeJTI(ctx context.Context, jti string, expiry time.Time) error
}

// JWTMiddleware validates Bearer and DPoP JWT access tokens and injects the
// claims into the request context. DPoP is not opt-in: a token carrying
// cnf.jkt always requires a valid proof, and so does any request presented
// under the DPoP authorization scheme.
type JWTMiddleware struct {
	jwks           JWKSProvider
	issuerProvider output.IssuerProvider
	obs            *observability.Provider
	dpop           *DPoPJWTConfig // optional: nil = 60s freshness default; never disables DPoP validation
	audience       string         // optional: expected aud claim; empty disables audience check
	proofStore     DPoPProofStore // optional: replay store for DPoP proof JTIs
}

// NewJWTMiddleware creates a JWT validation middleware that verifies a token's
// signature against the issuer's JWKS, its `iss` claim and its expiry — and,
// for DPoP-bound tokens, the proof itself: the DPoP scheme, `htm`/`htu`/`ath`,
// freshness within the proof-lifetime window (60s unless WithDPoP sets it),
// and the `cnf.jkt` binding. It does not apply the two relational controls:
// whether the token was minted for this resource, and whether this proof has
// been seen before.
//
// Reaching for this shorter signature is precisely the audience-confusion and
// DPoP-replay footgun that [NewResourceJWTMiddleware] exists to make
// impossible; it remains only for callers that have deliberately established
// both controls elsewhere.
//
// Deprecated: NewJWTMiddleware provides NO audience isolation and NO DPoP
// proof-replay protection — it accepts any token the issuer signed, including
// one minted for a different resource server, and never consumes DPoP proof
// JTIs, leaving a captured proof replayable against the same method and URL
// for its full lifetime. Use [NewResourceJWTMiddleware], which requires the
// resource URI (RFC 8707) and a proof store and panics at construction if
// either is missing.
func NewJWTMiddleware(jwks JWKSProvider, issuerProvider output.IssuerProvider, obs *observability.Provider) *JWTMiddleware {
	if issuerProvider == nil {
		panic("shared.NewJWTMiddleware: issuerProvider is required")
	}
	return &JWTMiddleware{jwks: jwks, issuerProvider: issuerProvider, obs: obs}
}

// NewResourceJWTMiddleware creates a JWT validation middleware configured for
// a specific resource server. audience MUST be the resource URI (RFC 8707) and
// proofStore MUST be a replay store for DPoP proof JTIs — both are required
// because forgetting either re-opens the audience-confusion and DPoP-replay
// classes of bug, respectively. dpopCfg sets the proof-freshness window, and
// nothing else: the zero value leaves DPoP validation fully on at the 60s
// default, because a token carrying cnf.jkt is validated whatever dpopCfg
// says. DPoP enforcement is token-intrinsic and cannot be turned off from
// this constructor — see the [crypto.IsDPoPBound] call site in Wrap.
//
// Every 401 advertises the schemes that would actually work — both, or DPoP
// alone once the token is known to be bound — regardless of dpopCfg, for the
// same reason: this resource always accepts, and for a bound token always
// requires, DPoP (RFC 9449 §7.1).
//
// Panics if audience or proofStore is empty/nil — the failure mode of
// "I shipped a resource server with audience=\"\"" is precisely what this
// constructor exists to make impossible.
func NewResourceJWTMiddleware(
	jwks JWKSProvider,
	issuerProvider output.IssuerProvider,
	audience string,
	proofStore DPoPProofStore,
	dpopCfg DPoPJWTConfig,
	obs *observability.Provider,
) *JWTMiddleware {
	if issuerProvider == nil {
		panic("shared.NewResourceJWTMiddleware: issuerProvider is required")
	}
	if audience == "" {
		panic("shared.NewResourceJWTMiddleware: audience is required for resource-server use (see api/shared/jwt_middleware.go and RFC 8707)")
	}
	if proofStore == nil {
		panic("shared.NewResourceJWTMiddleware: proofStore is required for resource-server use; pass DPoPNonceStore from the composition root (see audit 2026-05-18 MEDIUM finding on DPoP replay)")
	}
	m := &JWTMiddleware{
		jwks:           jwks,
		issuerProvider: issuerProvider,
		obs:            obs,
		audience:       audience,
		proofStore:     proofStore,
	}
	if dpopCfg.ProofLifetime > 0 {
		cfg := dpopCfg
		m.dpop = &cfg
	}
	return m
}

// WithDPoP sets the DPoP proof-freshness window. It does not switch DPoP
// validation on, and it does not change what a 401 advertises: a token
// carrying cnf.jkt is validated either way, and the challenge names DPoP
// either way.
//
// A non-positive ProofLifetime means "use the 60s default", exactly as in
// [NewResourceJWTMiddleware]. The two must agree: storing a zero window
// verbatim would reject every proof while the challenge still advertised
// DPoP, leaving a compliant client that sends a perfectly fresh proof in a
// permanent 401 — and it would give the same zero value opposite meanings
// across the two public entry points third parties build on.
func (m *JWTMiddleware) WithDPoP(cfg DPoPJWTConfig) *JWTMiddleware {
	if cfg.ProofLifetime <= 0 {
		m.dpop = nil
		return m
	}
	c := cfg
	m.dpop = &c
	return m
}

// WithAudience configures the expected audience (resource URI) for tokens
// accepted by this middleware. Once set, tokens whose `aud` claim does not
// contain `aud` are rejected with 401. Required for every resource-server
// deployment of this middleware (RFC 9068 §4, RFC 8707).
func (m *JWTMiddleware) WithAudience(aud string) *JWTMiddleware {
	m.audience = aud
	return m
}

// WithDPoPProofStore enables DPoP proof-JTI replay detection at the resource
// server. Without a store the middleware verifies the proof's structure and
// binding but does not consume the JTI, leaving a replay window equal to
// ProofLifetime. Required for any resource exposed to network attackers.
func (m *JWTMiddleware) WithDPoPProofStore(s DPoPProofStore) *JWTMiddleware {
	m.proofStore = s
	return m
}

// authChallenge builds a WWW-Authenticate value naming every scheme that could
// actually work for this caller. A DPoP-bound token has exactly one way in; for
// anything else — including a token that could not be validated far enough to
// tell — both schemes are honest, because the resource accepts both.
//
// Every 401 out of this middleware goes through here. Fixing only the tokenless
// challenge would leave the dead end live on the paths a client hits far more
// often: a DPoP client whose bound token merely expired would be told "Bearer",
// retry under Bearer, and be rejected for using it.
//
// dpopErr is the error code for the DPoP challenge. The Bearer challenge always
// carries invalid_token: it is the RFC 6750 §3.1 code for a token that was
// presented and rejected, and a DPoP-specific code such as invalid_dpop_proof
// must not appear on a Bearer challenge, whose parameter vocabulary RFC 6750
// defines. Each scheme says what its own specification lets it say.
//
// Both challenges carry their code. Leaving the Bearer half bare would drop the
// signal RFC 6750 §3 says SHOULD be there — "the resource server SHOULD include
// the error attribute" — which is what a client library reads to choose between
// refreshing the token and starting authorization over.
//
// description adds error_description, but only when the line names a single
// scheme. Two challenges on one line are unambiguous per RFC 9110 §11.6.1 to a
// full parser, and a client that simply splits the field on "," still gets two
// complete challenges — but a second parameter on either would land between
// them and read as a challenge of its own. With one scheme the worst case is a
// trailing fragment the client does not recognize, the complete challenge still
// in the part before it.
//
// description must be accurate for the specific cause. A fixed string on a
// branch reachable through several causes is worse than none: it points the
// caller at the wrong thing. WriteOAuthError carries the reason in the body
// either way.
func authChallenge(bound bool, dpopErr, description string) string {
	if dpopErr == "" {
		if bound {
			return "DPoP"
		}
		return "Bearer, DPoP"
	}
	dpop := `DPoP error="` + dpopErr + `"`
	if bound {
		if description != "" {
			dpop += `, error_description="` + sanitizeChallengeText(description) + `"`
		}
		return dpop
	}
	return `Bearer error="` + errInvalidToken + `", ` + dpop
}

// sanitizeChallengeText reduces s to what may appear inside an RFC 7235
// quoted-string: DQUOTE and backslash would need escaping, and control
// characters would let a value split the header. Some of this text originates
// in wrapped errors, so it is filtered rather than trusted, and bounded so a
// long chain cannot bloat the response.
func sanitizeChallengeText(s string) string {
	const maxLen = 160
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= maxLen {
			break
		}
		if r == '"' || r == '\\' || r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Wrap returns an http.Handler that validates the Bearer or DPoP JWT.
// On success, injects *crypto.AccessTokenClaims into context.
// On failure, returns 401 with WWW-Authenticate header.
func (m *JWTMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header (Bearer or DPoP scheme).
		rawToken, scheme := ExtractAuthToken(r)
		if rawToken == "" {
			// Fall back to legacy Bearer-only extraction for backward compatibility.
			rawToken = ExtractBearerToken(r)
			if rawToken != "" {
				scheme = "Bearer"
			}
		}

		if rawToken == "" {
			// Advertise both schemes unconditionally (RFC 9449 §7.1). DPoP
			// validation is token-intrinsic — see the crypto.IsDPoPBound call
			// site below — so this resource always accepts DPoP and always
			// requires it for a bound token. Gating the challenge on m.dpop
			// would let a resource answer "Bearer" and then reject the caller
			// for using Bearer, which is a discoverability dead end, not a
			// narrower security posture.
			//
			// One field line, not two: WWW-Authenticate is 1#challenge
			// (RFC 9110 §11.6.1), and a client reading it with a
			// first-value-wins accessor — Go's own http.Header.Get, and most
			// hand-rolled parsers — would see only "Bearer" if these were
			// split across lines, which is the outcome this change exists to
			// remove.
			w.Header().Set("WWW-Authenticate", authChallenge(false, "", ""))
			WriteOAuthError(w, http.StatusUnauthorized, errInvalidToken, "access token required")
			return
		}

		issuer, err := m.issuerProvider.Issuer(r.Context())
		if err != nil {
			m.obs.Logger.ErrorContext(r.Context(), "resolve issuer failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		jwks, err := m.jwks.BuildJWKS(r.Context())
		if err != nil {
			m.obs.Logger.ErrorContext(r.Context(), "jwt middleware: failed to build JWKS", "error", err)
			w.Header().Set("WWW-Authenticate", authChallenge(false, errInvalidToken, ""))
			WriteOAuthError(w, http.StatusUnauthorized, errInvalidToken, "token validation unavailable")
			return
		}

		claims, err := crypto.VerifyAccessTokenWithIssuer(rawToken, jwks, issuer)
		if err != nil {
			m.obs.Logger.DebugContext(r.Context(), "jwt middleware: token verification failed", "error", err)
			// Boundness is unknowable here — the token did not verify, so its
			// cnf claim is not trustworthy. This is the branch an expired
			// DPoP token lands on, and the one that most needs to name DPoP.
			w.Header().Set("WWW-Authenticate", authChallenge(false, errInvalidToken, ""))
			WriteOAuthError(w, http.StatusUnauthorized, errInvalidToken, "invalid or expired token")
			return
		}

		bound := crypto.IsDPoPBound(claims)

		// Audience enforcement (RFC 9068 §4, RFC 8707): when the middleware is
		// configured with an expected audience, the token's `aud` must contain
		// it. A token minted for resource A must not be honored by resource B
		// — this is the load-bearing per-resource isolation check.
		//
		// An empty audience skips the check entirely, degrading to issuer-only
		// trust. NewResourceJWTMiddleware rejects an empty audience at
		// construction, so a resource server built through it cannot start in
		// that state — but WithAudience("") can still reach this branch, as
		// can the deprecated NewJWTMiddleware on its own.
		if m.audience != "" && !claims.HasAudience(m.audience) {
			m.obs.Logger.DebugContext(r.Context(), "jwt middleware: audience mismatch",
				"expected", m.audience, "got", claims.Audience)
			w.Header().Set("WWW-Authenticate", authChallenge(bound, errInvalidToken, "audience mismatch"))
			WriteOAuthError(w, http.StatusUnauthorized, errInvalidToken, "token audience does not match this resource")
			return
		}

		// DPoP enforcement (RFC 9449 §7.1), on two independent triggers:
		//
		//   - the token says so: cnf.jkt marks it DPoP-bound, so a proof is
		//     required no matter how the caller framed the request; and
		//   - the request says so: the DPoP authorization scheme means the
		//     caller claims to be presenting proof-of-possession, so it must
		//     actually present one. Skipping the check for an unbound token
		//     would let the resource advertise DPoP in its challenge and then
		//     accept the scheme with no proof at all.
		//
		// Both are deliberately independent of m.dpop, which only overrides
		// the proof-freshness window (validateDPoPBinding below). It is not an
		// on/off switch, and adding it here to "align" the two would turn a
		// nil config into a real bypass: a DPoP-bound token would then be
		// accepted with no proof. TestJWTMiddleware_ZeroDPoPConfig_* and
		// TestJWTMiddleware_DPoPScheme_* lock both triggers in.
		if bound || scheme == "DPoP" {
			if code, err := m.validateDPoPBinding(r, rawToken, claims, scheme); err != nil {
				m.obs.Logger.DebugContext(r.Context(), "jwt middleware: DPoP binding validation failed", "error", err)

				// An unbound token reached here by choosing the DPoP scheme,
				// and Bearer still works for it — naming both schemes is the
				// message, and a two-scheme line carries no description.
				//
				// A bound token has one scheme, so its challenge carries the
				// actual reason rather than a fixed string: this branch serves
				// a token sent under Bearer (no proof offered at all), a
				// missing DPoP header, and a proof that failed validation, and
				// naming the wrong one sends the caller to the wrong fix.
				w.Header().Set("WWW-Authenticate", authChallenge(bound, code, err.Error()))
				WriteOAuthError(w, http.StatusUnauthorized, code, err.Error())
				return
			}
		}

		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// validateDPoPBinding validates DPoP proof-of-possession for a request that
// either carries a DPoP-bound access token or was presented under the DPoP
// authorization scheme. Every check applies to both cases except the cnf.jkt
// comparison, which an unbound token has nothing to compare against.
//
// It returns the error code that fits the cause. A token presented under the
// wrong scheme is an invalid_token — RFC 9449 §7.2 says such a request is
// rejected per RFC 6750 — while everything downstream of that is a fault in the
// proof, and invalid_dpop_proof (RFC 9449 §7.1) tells the client to re-sign
// rather than to go get another token.
func (m *JWTMiddleware) validateDPoPBinding(r *http.Request, rawToken string, claims *crypto.AccessTokenClaims, scheme string) (string, error) {
	// DPoP-bound tokens MUST use the DPoP scheme, not Bearer (RFC 9449 §7.1).
	// Only a bound token can reach this branch: an unbound one is here because
	// the scheme already is DPoP.
	if scheme != "DPoP" {
		return errInvalidToken, fmt.Errorf("DPoP-bound token must use DPoP authorization scheme")
	}

	// DPoP proof header is required. Wrap passes this text to the client
	// verbatim, and both a bound token and an unbound one presented under the
	// DPoP scheme land here — so it must not assert the token is bound, which
	// would misdirect an operator reading the 401 body.
	dpopProof := r.Header.Get("DPoP")
	if dpopProof == "" {
		return errInvalidDPoPProof, fmt.Errorf("DPoP proof header required when using the DPoP authorization scheme")
	}

	// Compute ath (access token hash) — base64url(SHA-256(access_token)).
	ath := crypto.ComputeATH(rawToken)

	proofLifetime := 60 * time.Second
	if m.dpop != nil {
		proofLifetime = m.dpop.ProofLifetime
	}

	// Reconstruct request URL for htu validation.
	reqURL := RequestURL(r)

	result, err := crypto.ValidateProof(dpopProof, r.Method, reqURL, "", ath, proofLifetime)
	if err != nil {
		return errInvalidDPoPProof, fmt.Errorf("DPoP proof validation failed: %w", err)
	}

	// Verify that the proof's JKT matches the token's cnf.jkt, BEFORE consuming
	// the JTI, so that an attacker holding a bound token but not its key cannot
	// burn store entries with proofs signed by the wrong key.
	//
	// An unbound token reaching here came in under the DPoP scheme. There is no
	// cnf.jkt to compare against, so this step is skipped — the proof was still
	// required and still validated above. Two consequences, both deliberate:
	//
	//   - the proof demonstrates possession of some key, not of the key the
	//     token was issued to, because no binding exists to check it against.
	//     What it buys is that the resource stops accepting, in silence, a
	//     scheme it advertises as proof-carrying; and
	//   - the ordering guard above does not apply. Anyone holding an unbound
	//     token for this resource can self-sign proofs with chosen JTIs and
	//     drive ConsumeJTI writes, each retained for 2x ProofLifetime. That is
	//     storage-growth pressure, not a bypass — the JTIs it can burn are its
	//     own, and guessing a legitimate random JTI to burn is impractical —
	//     but the same holder can already spend the token on real requests, so
	//     the store is not a new lever. Revisit if proof stores ever become a
	//     constrained resource.
	if bound := crypto.IsDPoPBound(claims); bound {
		expectedJKT, _ := claims.Cnf["jkt"].(string)
		if result.JKT != expectedJKT {
			return errInvalidDPoPProof, fmt.Errorf("DPoP proof key does not match token binding")
		}
	}

	// Cap the JTI before it is used as a store key. On the unbound path the
	// JKT comparison above is skipped, so any holder of an unbound token for
	// this resource can self-sign proofs carrying freely chosen JTI strings,
	// and NewResourceJWTMiddleware directs operators to pass the same
	// DPoPNonceStore the token endpoint uses — a shared namespace, soon to be
	// SQL- or Redis-backed. Bounding the key length keeps a caller from
	// choosing how much room each of its entries occupies for the
	// 2x ProofLifetime they are retained.
	if len(result.JTI) > maxDPoPProofJTILen {
		return errInvalidDPoPProof, fmt.Errorf("DPoP proof jti exceeds %d bytes", maxDPoPProofJTILen)
	}

	// Consume the proof JTI for replay detection. Without this the binding is
	// verified per-request but a captured proof can be replayed against the
	// same method/URL within ProofLifetime. The token endpoint already
	// consumes via dpopStore.ConsumeJTI; this mirrors that at the resource
	// server.
	//
	// With no store configured this step is skipped silently — nothing is
	// logged, so a resource server missing replay protection gives no runtime
	// signal at all. That is why NewResourceJWTMiddleware makes the store
	// mandatory at construction instead.
	if m.proofStore != nil {
		expiry := time.Now().Add(proofLifetime * 2)
		if storeErr := m.proofStore.ConsumeJTI(r.Context(), result.JTI, expiry); storeErr != nil {
			return errInvalidDPoPProof, fmt.Errorf("DPoP proof replay detected: %w", storeErr)
		}
	}

	return "", nil
}
