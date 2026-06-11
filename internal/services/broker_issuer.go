// Package services contains application services. BrokerIssuer is the
// orchestrator between the unified resource model and the per-protocol
// BrokerProtocol adapters (the architecture doc, design doc §4.4):
//
//   - resolves the active broker_grants row for (user, broker_provider)
//   - enforces the three-bound: requested fine scopes map to
//     upstream scopes that must be a subset of the granted upstream
//     scope set
//   - decrypts the credential, dispatches to the registered
//     BrokerProtocol adapter, persists any rotated credential under the
//     optimistic-lock contract
//   - writes the issuances audit row (carries agent_id / agent_chain so
//     forensic queries work even though broker tokens cannot carry these
//     claims on the wire)
//
// Encryption owner-context: the credential bytes are scoped under
// "broker:{userID}:{providerID}". See
// internal/adapters/sqlite/broker_grant_store_test.go's
// TestBrokerGrantStore_CredentialData_StoredByteForByte for the
// storage-side guard that catches a missing Encrypt call before Create.
package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/brokerproto"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// BrokerIssuer dispatches Resource.BackendKind == broker requests to the
// matching BrokerProtocol adapter. Wired in cmd/authserver/serve.go (Inc
// 71) and consumed by TokenExchangeService via the
// internal/issuer.Registry.
//
// No metrics are emitted in this increment: the legacy UpstreamTokenIssuedTotal /
// UpstreamTokenIssuanceDuration instruments are deliberately left for the soon-dead
// VendService path, and a dedicated authserver_broker_vend_* family is
// added with the wiring in . Tracing, logging, and audit are the
// observability surfaces here.
type BrokerIssuer struct {
	grants    output.BrokerGrantStore
	encryptor output.DataEncryptor
	issuances output.IssuanceStore
	adapters  *brokerproto.Registry
	audit     AuditRecorder
	logger    *slog.Logger
	tracer    trace.Tracer
}

// Compile-time substitution gate: BrokerIssuer must satisfy the unified
// Issuer interface so internal/issuer.Registry can dispatch to it.
var _ Issuer = (*BrokerIssuer)(nil)

// NewBrokerIssuer constructs a BrokerIssuer. The encryptor and adapter
// registry are required dependencies; audit may be nil (matches the
// nil-safe convention on AuditRecorder used elsewhere in this package).
func NewBrokerIssuer(
	grants output.BrokerGrantStore,
	encryptor output.DataEncryptor,
	issuances output.IssuanceStore,
	adapters *brokerproto.Registry,
	obs *observability.Provider,
	auditor AuditRecorder,
) *BrokerIssuer {
	return &BrokerIssuer{
		grants:    grants,
		encryptor: encryptor,
		issuances: issuances,
		adapters:  adapters,
		audit:     auditor,
		logger:    obs.Logger.With("component", "broker_issuer"),
		tracer:    obs.Tracer,
	}
}

// Kind reports the BackendKind this Issuer handles. Used by
// internal/issuer.Registry for self-registration.
func (b *BrokerIssuer) Kind() resource.BackendKind { return resource.BackendBroker }

// Issue produces an upstream-narrowed access token for the requested
// Broker resource. Pseudocode mirrors the architecture doc:
//
//  1. Look up the active grant for (UserID, Provider.ID); nil → consent
//     required.
//  2. Map requested fine scopes to upstream scopes via the resource
//     catalog and verify ⊆ grant.ScopesGranted; otherwise consent
//     required (cause: scope_insufficient).
//  3. Decrypt CredentialData under owner context "broker:{user}:{prov}".
//  4. Look up the BrokerProtocol adapter by Provider.Protocol.
//  5. Vend; if the adapter returns an updatedCredential, re-encrypt and
//     persist via UpdateWithVersion. ErrBrokerGrantConflict means another
//     vend rotated concurrently — log a warning and continue.
//  6. Insert the issuance audit row (single-audience).
//  7. Record the audit event.
func (b *BrokerIssuer) Issue(ctx context.Context, req IssueRequest) (*IssueResponse, error) {
	ctx, span := b.tracer.Start(ctx, "BrokerIssuer.Issue")
	defer span.End()

	if req.Resource == nil || !req.Resource.IsBroker() || req.Provider == nil {
		err := errors.New("broker issuer requires a broker resource and resolved provider")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("user_id", req.SubjectUserID),
		attribute.String("actor_client_id", req.ActorClientID),
		attribute.String("resource_id", req.Resource.ID),
		attribute.String("resource_slug", req.Resource.Slug),
		attribute.String("broker_provider_id", req.Provider.ID),
		attribute.String("broker_provider_slug", req.Provider.Slug),
		attribute.String("broker_protocol", string(req.Provider.Protocol)),
		attribute.Int("scope_count", len(req.Scopes)),
	)

	// 1. Load active grant. Get filters revoked_at IS NULL, so a revoked
	// grant returns (nil, nil) — collapsed into the same "consent
	// required" branch as a never-connected user.
	grant, err := b.grants.Get(ctx, req.SubjectUserID, req.Provider.ID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		b.logger.ErrorContext(ctx, "broker grant lookup failed",
			"user_id", req.SubjectUserID,
			"broker_provider_id", req.Provider.ID,
			"error", err,
		)
		return nil, fmt.Errorf("look up broker grant: %w", err)
	}
	if grant == nil {
		span.SetStatus(codes.Error, "consent_required")
		b.logger.InfoContext(ctx, "broker vend denied: no active grant",
			"user_id", req.SubjectUserID,
			"broker_provider_slug", req.Provider.Slug,
		)
		return nil, &domain.ConsentRequiredError{
			ProviderSlug: req.Provider.Slug,
			Cause:        domain.CauseConsentMissing,
		}
	}

	// 2. Map fine scopes → upstream scopes via the resource catalog and
	// enforce the broker-side bound:
	//   requested ⊆ resource.Scopes[].Upstream  (lookup)
	//   upstream  ⊆ grant.ScopesGranted          (consent)
	upstreamScopes, err := mapToUpstreamScopes(req.Resource, req.Scopes)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		b.logger.WarnContext(ctx, "broker vend denied: requested scope absent from resource catalog",
			"user_id", req.SubjectUserID,
			"resource_slug", req.Resource.Slug,
			"requested_scopes", req.Scopes,
		)
		return nil, err
	}
	if missing := scopesNotIn(upstreamScopes, grant.ScopesGranted); len(missing) > 0 {
		span.SetStatus(codes.Error, "consent_required:scope_insufficient")
		b.logger.InfoContext(ctx, "broker vend denied: upstream scopes not granted",
			"user_id", req.SubjectUserID,
			"broker_provider_slug", req.Provider.Slug,
			"missing_upstream_scopes", missing,
		)
		return nil, &domain.ConsentRequiredError{
			ProviderSlug:  req.Provider.Slug,
			Cause:         domain.CauseScopeInsufficient,
			MissingScopes: missing,
		}
	}

	// 3. Decrypt the persisted credential. Owner context is keyed on
	// (user, provider) — strictly distinct from the legacy "connection:"
	// prefix used by connection.Connection.OwnerContext.
	ownerContext := brokerOwnerContext(req.SubjectUserID, req.Provider.ID)
	plaintext, err := b.encryptor.Decrypt(ctx, grant.CredentialData, ownerContext)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		b.logger.ErrorContext(ctx, "broker credential decrypt failed",
			"user_id", req.SubjectUserID,
			"broker_provider_slug", req.Provider.Slug,
			"error", err,
		)
		return nil, fmt.Errorf("decrypt broker credential: %w", err)
	}

	// 4. Resolve the BrokerProtocol adapter. The registry returns
	// domain.ErrAdapterNotRegistered on miss; surface that sentinel
	// untouched so the caller can errors.Is on it uniformly.
	adapter, err := b.adapters.Lookup(string(req.Provider.Protocol))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		b.logger.ErrorContext(ctx, "broker protocol adapter not registered",
			"broker_provider_slug", req.Provider.Slug,
			"protocol", string(req.Provider.Protocol),
		)
		return nil, err
	}

	// 5. Vend.
	accessToken, expiresIn, updatedCred, err := adapter.Vend(ctx, req.Provider, req.Resource, plaintext, req.Scopes)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())

		// classify upstream-side failures into ConsentRequiredError
		// with a fine-grained DeniedReason. Direct-path callers continue to
		// receive ConsentRequiredError shapes (CauseConsentMissing /
		// CauseScopeInsufficient); only the new DeniedReason field is added.
		switch {
		case errors.Is(err, output.ErrUpstreamInvalidGrant):
			b.logger.InfoContext(ctx, "broker vend denied: upstream invalid_grant",
				"user_id", req.SubjectUserID,
				"broker_provider_slug", req.Provider.Slug,
				"error", err,
			)
			return nil, &domain.ConsentRequiredError{
				ProviderSlug: req.Provider.Slug,
				Cause:        domain.CauseConsentMissing,
				DeniedReason: "invalid_grant",
			}
		case errors.Is(err, output.ErrUpstreamUnavailable):
			b.logger.WarnContext(ctx, "broker vend denied: upstream unavailable",
				"user_id", req.SubjectUserID,
				"broker_provider_slug", req.Provider.Slug,
				"error", err,
			)
			return nil, &domain.ConsentRequiredError{
				ProviderSlug: req.Provider.Slug,
				Cause:        domain.CauseConsentMissing,
				DeniedReason: "upstream_error",
			}
		case errors.Is(err, output.ErrUpstreamScopeDowngrade):
			b.logger.InfoContext(ctx, "broker vend denied: upstream scope downgrade",
				"user_id", req.SubjectUserID,
				"broker_provider_slug", req.Provider.Slug,
				"error", err,
			)
			return nil, &domain.ConsentRequiredError{
				ProviderSlug: req.Provider.Slug,
				Cause:        domain.CauseScopeInsufficient,
				DeniedReason: "scope_downgrade",
			}
		}

		// Unclassified — preserve direct-path error shape (pre-).
		b.logger.ErrorContext(ctx, "broker adapter vend failed",
			"user_id", req.SubjectUserID,
			"broker_provider_slug", req.Provider.Slug,
			"protocol", string(req.Provider.Protocol),
			"error", err,
		)
		return nil, fmt.Errorf("broker adapter vend: %w", err)
	}

	// 6. Persist any rotated credential under the optimistic-lock
	// contract. The store's UpdateWithVersion bumps version atomically;
	// ErrBrokerGrantConflict means a parallel vend already rotated this
	// row — that's correct and we keep the just-issued access token.
	if updatedCred != nil {
		encrypted, encErr := b.encryptor.Encrypt(ctx, updatedCred, ownerContext)
		if encErr != nil {
			span.RecordError(encErr)
			span.SetStatus(codes.Error, encErr.Error())
			b.logger.ErrorContext(ctx, "rotated broker credential encrypt failed",
				"user_id", req.SubjectUserID,
				"broker_provider_slug", req.Provider.Slug,
				"error", encErr,
			)
			return nil, fmt.Errorf("encrypt rotated broker credential: %w", encErr)
		}
		grant.CredentialData = encrypted
		grant.UpdatedAt = time.Now().UTC()
		if updateErr := b.grants.UpdateWithVersion(ctx, grant); updateErr != nil {
			if errors.Is(updateErr, domain.ErrBrokerGrantConflict) {
				span.AddEvent("broker_grant_rotation_conflict_ignored")
				b.logger.WarnContext(ctx, "broker grant rotation lost optimistic-lock race; another vend rotated concurrently",
					"user_id", req.SubjectUserID,
					"broker_provider_slug", req.Provider.Slug,
					"grant_id", grant.ID,
				)
			} else {
				span.RecordError(updateErr)
				span.SetStatus(codes.Error, updateErr.Error())
				b.logger.ErrorContext(ctx, "broker grant rotation persist failed",
					"user_id", req.SubjectUserID,
					"broker_provider_slug", req.Provider.Slug,
					"grant_id", grant.ID,
					"error", updateErr,
				)
				return nil, fmt.Errorf("persist rotated broker credential: %w", updateErr)
			}
		}
	}

	// 7. Write the issuance audit row. agent_id / agent_chain mirror the
	// JWT claim shape — broker tokens cannot carry them on the wire but
	// the persisted row preserves chain-origin forensics.
	now := time.Now().UTC()
	iss := &resource.Issuance{
		ID:            crypto.GenerateRandomString(16),
		SubjectUserID: req.SubjectUserID,
		ClientID:      req.ActorClientID,
		ResourceID:    req.Resource.ID,
		Scopes:        req.Scopes,
		BackendKind:   resource.BackendBroker,
		Revocable:     false, // broker tokens are not AS-revocable.
		IssuedAt:      now,
		ExpiresAt:     now.Add(time.Duration(expiresIn) * time.Second),
		JTI:           "", // broker has no AS-side jti.
		DPoPJKT:       req.DPoPJKT,
		AgentID:       agentIDOf(req.AgentIdentity),
	}
	iss.SetAgentChain(agentChainOf(req.AgentIdentity))
	if err := b.issuances.Insert(ctx, iss); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		b.logger.ErrorContext(ctx, "broker issuance insert failed",
			"user_id", req.SubjectUserID,
			"broker_provider_slug", req.Provider.Slug,
			"resource_slug", req.Resource.Slug,
			"error", err,
		)
		return nil, fmt.Errorf("insert broker issuance: %w", err)
	}

	// 8. Audit. Detail carries non-secret metadata only.
	if b.audit != nil {
		b.audit.Record(ctx, audit.NewEvent(
			audit.ActionUpstreamTokenIssued,
			req.SubjectUserID, req.ActorClientID, "",
			fmt.Sprintf("provider=%s resource=%s scopes=%s",
				req.Provider.Slug, req.Resource.Slug, strings.Join(req.Scopes, " ")),
		))
	}
	b.logger.InfoContext(ctx, "broker token vended",
		"user_id", req.SubjectUserID,
		"actor_client_id", req.ActorClientID,
		"resource_slug", req.Resource.Slug,
		"broker_provider_slug", req.Provider.Slug,
		"issuance_id", iss.ID,
	)

	return &IssueResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		IssuanceID:  iss.ID,
	}, nil
}

// brokerOwnerContext returns the encryption owner-context string used for
// broker_grants rows. The "broker:" prefix is intentionally distinct from
// the legacy connection.Connection.OwnerContext "connection:" prefix so the
// two stores can never cross-decrypt one another.
func brokerOwnerContext(userID, providerID string) string {
	return "broker:" + userID + ":" + providerID
}

// mapToUpstreamScopes resolves each requested fine scope to its declared
// upstream wire-format string from the resource catalog. A scope absent
// from the catalog is treated as a caller bug and surfaces
// domain.ErrScopeNotInCatalog. A catalog entry with an empty Upstream
// field contributes no upstream scope (e.g. a Mint-only entry on a
// shared-shape resource).
func mapToUpstreamScopes(res *resource.Resource, requested []string) ([]string, error) {
	catalog := make(map[string]string, len(res.Scopes))
	for _, sc := range res.Scopes {
		catalog[sc.Name] = sc.Upstream
	}
	out := make([]string, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))
	for _, fine := range requested {
		up, ok := catalog[fine]
		if !ok {
			return nil, fmt.Errorf("scope %q on resource %q: %w", fine, res.Slug, domain.ErrScopeNotInCatalog)
		}
		if up == "" {
			continue
		}
		if _, dup := seen[up]; dup {
			continue
		}
		seen[up] = struct{}{}
		out = append(out, up)
	}
	return out, nil
}

// scopesNotIn returns the elements of want that are not present in have.
// Returns a nil slice when want ⊆ have.
func scopesNotIn(want, have []string) []string {
	if len(want) == 0 {
		return nil
	}
	haveSet := make(map[string]struct{}, len(have))
	for _, s := range have {
		haveSet[s] = struct{}{}
	}
	var missing []string
	for _, s := range want {
		if _, ok := haveSet[s]; !ok {
			missing = append(missing, s)
		}
	}
	return missing
}

// agentIDOf returns claims.AgentID or "" when claims is nil.
func agentIDOf(claims *AgentIdentityClaims) string {
	if claims == nil {
		return ""
	}
	return claims.AgentID
}

// agentChainOf returns claims.AgentChain or nil when claims is nil. The
// caller passes the result to Issuance.SetAgentChain which truncates to
// resource.MaxAgentChainLength.
func agentChainOf(claims *AgentIdentityClaims) []string {
	if claims == nil {
		return nil
	}
	return claims.AgentChain
}
