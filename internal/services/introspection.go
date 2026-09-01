package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// JWKSBuildProvider provides the JWKS key set for JWT verification.
type JWKSBuildProvider interface {
	BuildJWKS(ctx context.Context) (*jose.JSONWebKeySet, error)
}

// ResourceRuntimeResolver resolves a Resource by the slug or URI a token names
// in aud, so introspection can tell a resource server asking about a token
// minted for it apart from a stranger asking about a token that is none of its
// business. Satisfied by *ResourceRegistry.
//
// The lookup deliberately runs from the audience, not from the caller. Asking
// "which Resource does this client serve?" has no single answer —
// policy.runtime.client_ids is documented N:N, and one client legitimately acts
// for several Resources across calls — so a client bound to two of them would
// resolve ambiguously and be refused everywhere. Asking "for the Resource this
// token is for, is this client authorized?" has exactly one answer, and it is
// also the question RFC 7662 §4 poses.
type ResourceRuntimeResolver interface {
	Resolve(ctx context.Context, slugOrURI string) (*resource.Resource, error)
}

// IntrospectionService implements input.IntrospectionPort (RFC 7662).
type IntrospectionService struct {
	jwks           JWKSBuildProvider
	revocation     output.RevocationStore
	machineTokens  output.MachineTokenStore // optional: for machine token revocation checks
	clients        output.ClientStore
	users          output.UserStore
	audit          AuditRecorder
	issuerProvider output.IssuerProvider
	resources      ResourceRuntimeResolver // optional: enables the resource-server ownership branch
	logger         *slog.Logger
	tracer         trace.Tracer
	metrics        *observability.Metrics
}

var _ input.IntrospectionPort = (*IntrospectionService)(nil)

// NewIntrospectionService creates a new introspection service.
func NewIntrospectionService(
	jwks JWKSBuildProvider,
	revocation output.RevocationStore,
	machineTokens output.MachineTokenStore,
	clients output.ClientStore,
	users output.UserStore,
	issuerProvider output.IssuerProvider,
	obs *observability.Provider,
	auditor AuditRecorder,
) *IntrospectionService {
	if issuerProvider == nil {
		panic("services.NewIntrospectionService: issuerProvider is required")
	}
	return &IntrospectionService{
		jwks:           jwks,
		revocation:     revocation,
		machineTokens:  machineTokens,
		clients:        clients,
		users:          users,
		audit:          auditor,
		issuerProvider: issuerProvider,
		logger:         obs.Logger,
		tracer:         obs.Tracer,
		metrics:        obs.Metrics,
	}
}

// WithResourceRegistry attaches the unified ResourceRegistry so introspection
// can authorize a resource server asking about a token minted for it — the
// canonical RFC 7662 caller, which is never the token's own client.
//
// Without it, only the token's issuing client can introspect. That is
// fail-closed on purpose: an unwired registry must not widen who may ask.
// Set in cmd/authserver/serve.go and in the e2e harness.
func (s *IntrospectionService) WithResourceRegistry(r ResourceRuntimeResolver) {
	s.resources = r
}

// IntrospectToken validates a token and returns its active status and claims.
// Per RFC 7662 §2.2: invalid/expired/revoked tokens return {active: false}, not errors.
// Only client authentication failures return errors.
func (s *IntrospectionService) IntrospectToken(ctx context.Context, req input.IntrospectRequest) (*input.IntrospectResponse, error) {
	ctx, span := s.tracer.Start(ctx, "IntrospectionService.IntrospectToken")
	defer span.End()

	span.SetAttributes(attribute.String("client_id", req.ClientID))
	start := time.Now()

	// 1. Authenticate the requesting client. Past this point nothing reads
	// req.ClientID: every decision, log and audit row keys off caller.ID, the
	// identity the store confirmed. The two are equal whenever authentication
	// succeeded, but deciding — or recording — against a value the caller
	// supplied is the shape of the Keycloak azp bug this change exists to
	// avoid, and the equality holds only until some future normalization or
	// alternate auth path breaks it. The one exception is the refusal below,
	// where authentication failed and there is no confirmed identity to name.
	caller, reason := s.authenticateCaller(ctx, req)
	if reason != "" {
		return nil, s.denyClient(ctx, span, start, req.ClientID, reason)
	}

	// 2. Parse and verify the JWT.
	jwks, err := s.jwks.BuildJWKS(ctx)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to build JWKS for introspection", "error", err)
		return s.inactiveServerFault(ctx, start), nil
	}

	issuer, err := s.issuerProvider.Issuer(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve issuer: %w", err)
	}
	claims, err := crypto.VerifyAccessTokenWithIssuer(req.Token, jwks, issuer)
	if err != nil {
		s.logger.DebugContext(ctx, "introspection: token verification failed", "error", err)
		return s.denyInactive(ctx, start, caller.ID, "invalid_token", ""), nil
	}

	// 3. Verify the caller is entitled to ask about this token — the check
	// RevocationService has always performed and this endpoint never did.
	// A caller that does not qualify gets the same {active: false} body a dud
	// token gets, so the response cannot be read as "this token exists".
	//
	// This runs before the liveness lookups on purpose: those fire only for a
	// well-formed token, so deferring the check would leave a non-entitled
	// caller doing four more queries than a garbage token — the same oracle
	// moved from the body to the clock. It narrows that gap rather than closing
	// it, and the comment should not be read as claiming otherwise:
	// callerEntitlement itself makes one or two resource-store queries in the
	// non-owner branch, so a live token still costs measurably more than an
	// unparseable one. Closing it entirely means giving every path the same
	// query count, which is a larger change than this one.
	switch reason := s.callerEntitlement(ctx, caller.ID, issuer, claims); reason {
	case entitledYes:
		// fall through
	case entitledUndecidable:
		return s.inactiveServerFault(ctx, start), nil
	default:
		s.logger.WarnContext(ctx, "introspection attempt for token the caller is not entitled to",
			"requesting_client", caller.ID,
			"owning_client", claims.ClientID,
			"reason", reason,
		)
		return s.denyInactive(ctx, start, caller.ID, reason, claims.JTI), nil
	}

	// 4. Determine if this is a machine token by checking the machine token store.
	// Machine tokens include client_credentials, jwt-bearer, and token exchange grants.
	// Previously used sub == client_id heuristic, but jwt-bearer tokens have federated subjects.
	isMachineToken := false
	if s.machineTokens != nil && claims.JTI != "" {
		mt, mtErr := s.machineTokens.GetByJTI(ctx, claims.JTI)
		if mtErr == nil && mt != nil {
			isMachineToken = true
			if mt.Revoked {
				s.logger.InfoContext(ctx, "introspection: machine token revoked", "jti", claims.JTI, "client_id", claims.ClientID)
				return s.denyInactive(ctx, start, caller.ID, "machine_token_revoked", claims.JTI), nil
			}
		}
	}

	// 5. Check revocation for non-machine tokens via RevocationStore JTI blacklist.
	if !isMachineToken && s.revocation != nil && claims.JTI != "" {
		revoked, revErr := s.revocation.IsRevoked(ctx, claims.JTI)
		if revErr != nil {
			s.logger.WarnContext(ctx, "introspection: revocation check failed", "jti", claims.JTI, "error", revErr)
			return s.inactiveServerFault(ctx, start), nil
		}
		if revoked {
			s.logger.InfoContext(ctx, "introspection: token revoked", "jti", claims.JTI, "client_id", claims.ClientID)
			return s.denyInactive(ctx, start, caller.ID, "token_revoked", claims.JTI), nil
		}
	}

	// 6. Check that the issuing client is still active.
	issuingClient, err := s.clients.GetByID(ctx, claims.ClientID)
	if err != nil || !issuingClient.IsActive() {
		s.logger.InfoContext(ctx, "introspection: issuing client suspended or not found",
			"issuing_client_id", claims.ClientID,
		)
		return s.denyInactive(ctx, start, caller.ID, "issuing_client_inactive", claims.JTI), nil
	}

	// 7. Check that the subject user is still active (skip for machine tokens).
	if !isMachineToken && s.users != nil && claims.Subject != "" {
		u, userErr := s.users.GetByID(ctx, claims.Subject)
		if userErr != nil || !u.IsActive() {
			s.logger.InfoContext(ctx, "introspection: subject user disabled or not found",
				"sub", claims.Subject,
			)
			return s.denyInactive(ctx, start, caller.ID, "subject_inactive", claims.JTI), nil
		}
	}

	// 8. Token is active — build response.
	aud := ""
	if len(claims.Audience) > 0 {
		aud = claims.Audience[0]
	}

	// Determine token type and DPoP confirmation from claims.
	tokenType := "Bearer"
	var cnf map[string]interface{}
	if claims.Cnf != nil {
		if _, hasJKT := claims.Cnf["jkt"]; hasJKT {
			tokenType = "DPoP"
			cnf = claims.Cnf
		}
	}

	s.logger.InfoContext(ctx, "token introspected",
		"jti", claims.JTI,
		"client_id", claims.ClientID,
		"sub", claims.Subject,
		"requesting_client", caller.ID,
		"token_type", tokenType,
	)
	s.recordMetric(ctx, start, "active")

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionTokenIntrospected, "", caller.ID, "",
			"jti="+claims.JTI+" issuing_client="+claims.ClientID,
		))
	}

	return &input.IntrospectResponse{
		Active:    true,
		Scope:     claims.Scope,
		ClientID:  claims.ClientID,
		Sub:       claims.Subject,
		Aud:       aud,
		Iss:       claims.Issuer,
		Exp:       claims.Expiry,
		Iat:       claims.IssuedAt,
		Jti:       claims.JTI,
		TokenType: tokenType,
		Cnf:       cnf,
	}, nil
}

// authenticateCaller resolves and authenticates the requesting client,
// returning the empty string when it may proceed and a snake_case refusal
// reason otherwise.
//
// RFC 7662 §4 requires the endpoint to authenticate its callers, and RFC 6749
// §2.3 forbids relying on a public client's authentication to identify it — so
// a secret-less client carries no identity the ownership check could stand on
// and is refused outright. This is what the discovery document has advertised
// all along: introspection_endpoint_auth_methods_supported omits "none", while
// the revocation endpoint's list includes it.
//
// The refusals here are deliberately NOT cost-equalized, and the difference is
// observable: an unknown client_id, a public one and an omitted secret return
// in microseconds, while a registered confidential client with a wrong secret
// pays a full derivation. That gap tells an unauthenticated caller which
// client_ids are registered.
//
// Padding the early returns with a dummy comparison closes it and was tried
// here. It was withdrawn because the cure measured worse than the disease:
//
//   - What it buys is small. A client_id is 16 bytes of randomness
//     (crypto.GenerateClientID), so it cannot be enumerated, only confirmed —
//     and for a public client the value already travels in the authorize URL.
//   - What it costs is not. CompareClientSecret falls back to bcrypt at
//     DefaultBcryptCost whenever no client-secret pepper is configured, which
//     is the default. Measured at ~385ms, that is ~38 CPU-seconds of work per
//     second at the shipped 100 rps limiter — an unauthenticated caller
//     saturates the machine well below the configured ceiling.
//   - user_auth.go pays that cost on login only because RecordAuthFailure
//     locks the source address out after ten failures. This endpoint has no
//     such bound, so the same trade does not transfer.
//
// Closing it properly means deciding the pepper default and a per-caller bound
// together, neither of which belongs in a change about token ownership.
func (s *IntrospectionService) authenticateCaller(
	ctx context.Context, req input.IntrospectRequest,
) (*client.Client, string) {
	c, err := s.clients.GetByID(ctx, req.ClientID)
	if err != nil {
		return nil, reasonClientNotFound
	}
	if c.IsPublic() {
		return nil, reasonPublicClient
	}
	if req.ClientSecret == "" {
		return nil, reasonMissingClientSecret
	}
	if cmpErr := crypto.CompareClientSecret(c.SecretHash, req.ClientSecret); cmpErr != nil {
		return nil, reasonInvalidClientSecret
	}

	// Status last, once the secret is proven. This one is free to equalize:
	// both a suspended client and a wrong secret have reached here having paid
	// the same comparison, so neither the body nor the clock separates them.
	if !c.IsActive() {
		return nil, reasonClientNotActive
	}
	return c, ""
}

// Entitlement outcomes for a caller asking about a token. The three are kept
// apart because they are audited differently: only entitledNo is the probing
// signal operators grep for, and filing an operator misconfiguration or a store
// outage under that reason would bury it under the AS's own problems.
// Client-authentication refusal reasons. The split that matters is not whether
// the client_id names anything — it is whether reaching the refusal cost the
// caller a credential; see auditedRefusal.
const (
	reasonClientNotFound      = "client_not_found"
	reasonPublicClient        = "public_client"
	reasonMissingClientSecret = "missing_client_secret"
	reasonInvalidClientSecret = "invalid_client_secret"
	reasonClientNotActive     = "client_not_active"
)

// auditedRefusal reports whether a client-authentication refusal earns a
// durable audit row.
//
// Only the two that cost the caller something do. invalid_client_secret pays a
// full secret comparison, which is self-limiting, and client_not_active is only
// reached once that secret verified — so both name a caller that proved
// something, and a rising rate on either is a real signal.
//
// The other three are reachable with no credential at all: an unrecognized
// client_id, a public one, or simply omitting the secret. AuditService.Record
// writes synchronously in the request path, so auditing those turns an
// anonymous loop into one indexed INSERT per request. A public client_id is no
// protection either — it travels in the authorize URL and in browser redirects
// (see RevocationService), so an attacker who has seen one can aim the writes
// at a specific client and poison its audit trail. They stay visible in the
// error metric and a debug log.
//
// The whitelist is deliberate: a reason added later is not audited until
// someone decides it should be, and TestIntrospect_AuditedRefusals_AreCredentialed
// fails if that decision is made silently.
func auditedRefusal(reason string) bool {
	return reason == reasonInvalidClientSecret || reason == reasonClientNotActive
}

const (
	entitledYes         = ""                                // may proceed
	entitledNo          = "caller_not_authorized_for_token" // a stranger asking
	entitledAmbiguous   = "ambiguous_runtime_binding"       // operator misconfiguration
	entitledUndecidable = "resource_lookup_failed"          // the AS could not tell; never audited
)

// callerEntitlement reports whether requestingClient may learn this token's
// state, returning entitledYes or the reason it may not. Two ways to qualify:
//
//   - it issued the token — client_credentials and jwt-bearer clients checking
//     their own machine tokens, which is what every worked example in docs/
//     and every e2e scenario does today;
//   - it is authorized to act AS a Resource the token names in aud — an MCP
//     server asking about a token one of its clients presented. RFC 7662 §4
//     obliges the AS to answer that one: "If the token can be used only at
//     certain resource servers, the authorization server MUST determine whether
//     or not the token can be used at the resource server making the
//     introspection call."
//
// Everything else is a stranger asking about somebody else's token.
//
// One shape falls outside both branches: the fronted Mint dispatch issues a
// token whose client_id claim is the source Resource's slug rather than an
// OAuth client_id (token_exchange.go's Option β), so no caller can match on it.
// Those tokens do not reach here as active anyway — the issuing-client lookup
// further down resolves client_id against the client store and finds nothing,
// which has always reported them inactive to everybody, this change included.
func (s *IntrospectionService) callerEntitlement(
	ctx context.Context, requestingClient, issuer string, claims *crypto.AccessTokenClaims,
) string {
	if requestingClient == claims.ClientID {
		return entitledYes
	}
	if s.resources == nil {
		// Unwired registry admits only the issuing client. Fail closed on
		// purpose: an absent dependency must not widen who may ask.
		return entitledNo
	}

	ambiguous, undecidable := false, false
	for _, aud := range claims.Audience {
		// The issuer is what a resource-less machine token carries in aud
		// (mint_issuer.go), and it names the AS, not a Resource. Skipping it
		// is not an optimization: if a Resource were ever registered under the
		// issuer URL, resolving it would let that Resource's runtime clients
		// introspect every resource-less machine token in the deployment.
		// TokenExchangeService.resolveSourceForFronting skips it for the same
		// reason.
		if aud == "" || aud == issuer {
			continue
		}
		res, err := s.resources.Resolve(ctx, aud)
		switch {
		case err == nil:
			if s.resourceAuthorizes(ctx, res, requestingClient) {
				return entitledYes
			}
		case errors.Is(err, domain.ErrResourceNotFound):
			// This audience names no Resource — nothing to be authorized for.
			continue
		case errors.Is(err, domain.ErrAmbiguousResource):
			// Two Resources answer to one slug-or-URI. That is an operator
			// mistake, not a caller one, so it gets its own reason rather than
			// the probing signal — but it still denies, because guessing which
			// Resource was meant is exactly what must not happen here.
			ambiguous = true
		default:
			// The store failed for this entry. Keep going: another audience
			// may still authorize the caller, and refusing here would deny an
			// entitled caller over a decision the AS could have made. Only if
			// nothing authorizes does the failure become the answer.
			s.logger.ErrorContext(ctx, "introspection: resource lookup failed",
				"requesting_client", requestingClient,
				"aud", aud,
				"error", err,
			)
			undecidable = true
		}
	}

	switch {
	case undecidable:
		// A store failure outranks ambiguity: one is the AS breaking, the
		// other is a configuration the AS read correctly and refused.
		return entitledUndecidable
	case ambiguous:
		return entitledAmbiguous
	}
	return entitledNo
}

// resourceAuthorizes reports whether requestingClient may act AS res.
//
// policy.runtime.client_ids is the canonical answer. Deployments still on the
// retired slug==client_id convention fall through for one release, mirroring
// TokenExchangeService.resolveActorMCP so both gates retire it on the same
// schedule; remove that arm alongside this one.
func (s *IntrospectionService) resourceAuthorizes(
	ctx context.Context, res *resource.Resource, requestingClient string,
) bool {
	if slices.Contains(res.Policy.Runtime.ClientIDs, requestingClient) {
		return true
	}
	if res.Slug == requestingClient || res.URI == requestingClient {
		s.logger.WarnContext(ctx,
			"introspection: caller matched its resource via the deprecated slug==client_id convention; configure policy.runtime.client_ids on the resource",
			"requesting_client", requestingClient,
			"resource_slug", res.Slug,
		)
		return true
	}
	return false
}

// denyClient records the span, metric and audit trail for a client
// authentication failure and returns the error the handler surfaces as
// invalid_client. reason is snake_case: it lands in an audit Detail whose
// canonical form is greppable `key=value` pairs, so a value with a space in it
// would split across two fields.
//
// Which refusals earn an audit row is decided by auditedRefusal, on whether the
// caller had to prove a credential to reach one — not on whether the client_id
// names anything. The probing signal survives in the audited refusals and in
// the caller_not_authorized_for_token rows, which name an authenticated caller. Auth failures are the probing signal most worth watching,
// so they are audited like every other negative path.
func (s *IntrospectionService) denyClient(ctx context.Context, span trace.Span, start time.Time, clientID, reason string) error {
	span.RecordError(domain.ErrInvalidClient)
	span.SetStatus(codes.Error, reason)
	s.recordMetric(ctx, start, "error")
	if auditedRefusal(reason) {
		s.recordDenial(ctx, clientID, reason, "")
	} else {
		s.logger.DebugContext(ctx, "introspection: client authentication refused before any credential was checked",
			"reason", reason)
	}
	return domain.ErrInvalidClient
}

// inactiveServerFault reports a token inactive because the server could not
// decide, and deliberately writes no audit row.
//
// A failed introspection is audited so that probing leaves a trail. These two
// paths are not probing: the caller did nothing wrong and the AS failed, so a
// token.introspect_denied naming them misattributes an outage to whoever
// happened to be asking. Both already surface as an error/warn log and as an
// "inactive" metric, so nothing is lost — and during a JWKS or revocation-store
// outage *every* call takes this path, which would amplify audit writes exactly
// when the database is least able to absorb them.
func (s *IntrospectionService) inactiveServerFault(
	ctx context.Context, start time.Time,
) *input.IntrospectResponse {
	s.recordMetric(ctx, start, "inactive")
	return &input.IntrospectResponse{Active: false}
}

// denyInactive records the negative-path metric and audit trail, then returns
// the bare {active: false} body. Per RFC 7662 §4 an inactive response carries
// no other claim, which is also what keeps "not yours" and "not valid"
// indistinguishable on the wire.
func (s *IntrospectionService) denyInactive(
	ctx context.Context, start time.Time, clientID, reason, jti string,
) *input.IntrospectResponse {
	s.recordMetric(ctx, start, "inactive")
	s.recordDenial(ctx, clientID, reason, jti)
	return &input.IntrospectResponse{Active: false}
}

// recordDenial writes the audit row for a non-successful introspection. The
// endpoint is oracle-shaped, so the negative half is the half that matters:
// before this, a caller probing token values left no audit trail at all.
func (s *IntrospectionService) recordDenial(ctx context.Context, clientID, reason, jti string) {
	if s.audit == nil {
		return
	}
	detail := "reason=" + reason
	if jti != "" {
		detail += " jti=" + jti
	}
	s.audit.Record(ctx, audit.NewEvent(audit.ActionTokenIntrospectDenied, "", clientID, "", detail))
}

func (s *IntrospectionService) recordMetric(ctx context.Context, start time.Time, result string) {
	s.metrics.IntrospectionDuration.Record(ctx, time.Since(start).Seconds())
	s.metrics.IntrospectionTotal.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("result", result),
	))
}
