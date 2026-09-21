package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// GrantAdminService implements input.GrantAdminPort over the
// ConsentGrantStore + BrokerGrantStore + IssuanceStore.
//
// Cascade ownership: RevokeConsent owns the revocation cascade onto live
// Mint issuances per the data model The grant revocation and the
// cascade are NOT atomic — see RevokeConsent for the ordering and
// partial-success behavior.
type GrantAdminService struct {
	consents  output.ConsentGrantStore
	brokers   output.BrokerGrantStore
	issuances output.IssuanceStore
	audit     AuditRecorder
	logger    *slog.Logger
	tracer    trace.Tracer

	// Refresh-family cascade, set by WithRefreshFamilyCascade. Nil in
	// unit tests that did not opt in; then RevokeConsent revokes the
	// grant and the issuances and logs that families were not reached.
	tokens     output.TokenStore
	revocation output.RevocationStore
	resources  resourceByID
}

// resourceByID is the one ResourceStore method the family cascade needs:
// a consent grant carries the resource's id, a token family carries its
// URI, and the two meet here.
type resourceByID interface {
	GetByID(ctx context.Context, id string) (*resource.Resource, error)
}

var _ input.GrantAdminPort = (*GrantAdminService)(nil)

// NewGrantAdminService constructs a GrantAdminService.
func NewGrantAdminService(
	consents output.ConsentGrantStore,
	brokers output.BrokerGrantStore,
	issuances output.IssuanceStore,
	obs *observability.Provider,
	auditSvc AuditRecorder,
) *GrantAdminService {
	return &GrantAdminService{
		consents:  consents,
		brokers:   brokers,
		issuances: issuances,
		audit:     auditSvc,
		logger:    obs.Logger,
		tracer:    obs.Tracer,
	}
}

// WithRefreshFamilyCascade lets RevokeConsent reach the consenting
// client's own refresh-token families for the resource, not only the
// tokens exchanged from them. Without it a revoked consent stops every
// exchange but the client the user faced keeps refreshing, and each new
// access token it mints is a fresh subject token for anyone allowed to
// exchange it. Set in cmd/authserver and the e2e harness.
func (s *GrantAdminService) WithRefreshFamilyCascade(
	tokens output.TokenStore,
	revocation output.RevocationStore,
	resources resourceByID,
) {
	s.tokens = tokens
	s.revocation = revocation
	s.resources = resources
}

// ListForUser returns every consent + broker grant for the user. Both
// slices include revoked rows (the admin surface shows full history) and
// are ordered by created_at DESC per the underlying store contracts.
func (s *GrantAdminService) ListForUser(ctx context.Context, userID string) (input.UserGrants, error) {
	ctx, span := s.tracer.Start(ctx, "GrantAdminService.ListForUser")
	defer span.End()
	span.SetAttributes(attribute.String("user_id", userID))

	if userID == "" {
		err := domain.NewInvalidRequestError("user_id is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return input.UserGrants{}, err
	}

	consent, err := s.consents.ListForUser(ctx, userID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return input.UserGrants{}, fmt.Errorf("list consent grants: %w", err)
	}
	broker, err := s.brokers.ListForUser(ctx, userID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return input.UserGrants{}, fmt.Errorf("list broker grants: %w", err)
	}
	return input.UserGrants{Consent: consent, Broker: broker}, nil
}

// RevokeConsent soft-deletes the consent_grants row and cascades onto
// everything that exists because of it.
//
// What the cascade reaches, for a grant (user, client, resource):
//
//   - Every live Mint issuance minted under the grant — the client's own
//     tokens for the resource and every token exchanged from them, at any
//     depth (IssuanceStore.RevokeFamily follows the parent link). Their
//     jtis answer inactive at introspection and are refused as subject
//     tokens at the token endpoint from the moment the row is marked.
//   - Every active refresh-token family the client holds for the
//     resource, with its access-token jtis denylisted, so the client
//     cannot mint a fresh first-hop token either.
//
// Ordering: GetByID is called BEFORE Revoke so the (user, client,
// resource) triple is captured pre-mutation; the storage Revoke
// returns no row data and Get filters revoked rows out, so capturing
// the triple after the revocation isn't possible against the active
// store contract.
//
// Cascade-failure handling: if either cascade fails after the grant has
// been revoked, the system enters a partial-success state — grant gone,
// some live tokens linger until expiry. The grant revocation is the
// load-bearing security action (no NEW tokens can be minted), so we log
// loudly, mark the audit detail (cascade=failed / family_cascade=failed)
// and return nil. Alerting on those markers catches the case at runtime.
//
// Unknown id handling: if GetByID returns (nil, nil) the grant was
// never persisted; the cascade is a no-op and the storage Revoke is
// idempotent (zero-row UPDATE returns nil). The audit row records
// revoked_issuances=0 so the operator surface still gets a confirmation.
func (s *GrantAdminService) RevokeConsent(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "GrantAdminService.RevokeConsent")
	defer span.End()
	span.SetAttributes(attribute.String("grant_id", id))

	if id == "" {
		err := domain.NewInvalidRequestError("id is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	grant, err := s.consents.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("lookup consent grant: %w", err)
	}

	if err := s.consents.Revoke(ctx, id); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("revoke consent grant: %w", err)
	}

	revokedIssuances := 0
	cascadeFailed := false
	var userID, clientID, resourceID string
	if grant != nil {
		userID = grant.UserID
		clientID = grant.ClientID
		resourceID = grant.ResourceID
		n, cerr := s.issuances.RevokeFamily(ctx, userID, clientID, resourceID)
		if cerr != nil {
			cascadeFailed = true
			s.logger.ErrorContext(ctx, "issuance cascade revoke failed",
				"grant_id", id,
				"user_id", userID,
				"client_id", clientID,
				"resource_id", resourceID,
				"error", cerr,
			)
			span.RecordError(cerr)
		} else {
			revokedIssuances = n
		}
	}

	revokedFamilies := 0
	familyCascadeFailed := false
	if grant != nil {
		n, ferr := s.revokeRefreshFamilies(ctx, userID, clientID, resourceID)
		if ferr != nil {
			familyCascadeFailed = true
			s.logger.ErrorContext(ctx, "refresh family cascade revoke failed",
				"grant_id", id,
				"user_id", userID,
				"client_id", clientID,
				"resource_id", resourceID,
				"revoked_families", n,
				"error", ferr,
			)
			span.RecordError(ferr)
		}
		revokedFamilies = n
	}

	if s.audit != nil {
		detail := fmt.Sprintf("id=%s user_id=%s client_id=%s resource_id=%s revoked_issuances=%d revoked_families=%d",
			id, userID, clientID, resourceID, revokedIssuances, revokedFamilies)
		if cascadeFailed {
			detail += " cascade=failed"
		}
		if familyCascadeFailed {
			detail += " family_cascade=failed"
		}
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionConsentGrantRevokedAdmin,
			"admin", clientID, "",
			detail,
		))
	}

	s.logger.InfoContext(ctx, "consent grant revoked",
		"grant_id", id,
		"user_id", userID,
		"client_id", clientID,
		"resource_id", resourceID,
		"revoked_issuances", revokedIssuances,
		"cascade_failed", cascadeFailed,
		"revoked_families", revokedFamilies,
		"family_cascade_failed", familyCascadeFailed,
	)
	return nil
}

// revokeRefreshFamilies revokes every active refresh-token family the
// client holds for the resource on the user's behalf, and denylists the
// access-token jtis each family issued. Returns how many families were
// revoked; on error, how many were revoked before it.
//
// The family records the resource as the URI the authorization named
// (session.resource, canonical after /oauth/authorize resolved it); the
// grant records the resource's id. The resource row joins them. A grant
// whose resource no longer resolves has no families to match — a family
// cannot name a URI that was never registered, since consent itself is
// skipped for those.
//
// The matching families are collected first and revoked after: revoking
// moves a row out of the active filter, so paging and revoking in one
// pass would shift the offset under the reader and skip survivors.
func (s *GrantAdminService) revokeRefreshFamilies(ctx context.Context, userID, clientID, resourceID string) (int, error) {
	if s.tokens == nil || s.revocation == nil || s.resources == nil {
		s.logger.WarnContext(ctx, "refresh family cascade not wired; the consenting client's refresh families were not revoked",
			"client_id", clientID, "resource_id", resourceID)
		return 0, nil
	}

	res, err := s.resources.GetByID(ctx, resourceID)
	if errors.Is(err, domain.ErrResourceNotFound) || (err == nil && res == nil) {
		// The resource is gone. Its families cannot be told apart from
		// any other by URI any more, and the grant itself is already
		// revoked; nothing to do rather than a failure to report.
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("resolve grant resource: %w", err)
	}

	const page = 50
	var targets []string
	for offset := 0; ; offset += page {
		families, _, err := s.tokens.ListFamilies(ctx, output.FamilyFilter{
			UserID:   userID,
			ClientID: clientID,
			Status:   "active",
			Limit:    page,
			Offset:   offset,
		})
		if err != nil {
			return 0, fmt.Errorf("list token families: %w", err)
		}
		for i := range families {
			if families[i].Resource == res.URI {
				targets = append(targets, families[i].ID)
			}
		}
		if len(families) < page {
			break
		}
	}

	revoked := 0
	for _, id := range targets {
		changed, err := s.tokens.RevokeFamily(ctx, id)
		if err != nil {
			return revoked, fmt.Errorf("revoke family %s: %w", id, err)
		}
		if err := s.revocation.RevokeByFamily(ctx, id); err != nil {
			return revoked, fmt.Errorf("denylist jtis for family %s: %w", id, err)
		}
		if changed {
			revoked++
		}
	}
	return revoked, nil
}

// RevokeBroker soft-deletes the broker_grants row by id. There is no
// issuance cascade — already-vended upstream tokens are not AS-revocable.
//
// Audit detail enrichment (audit-followup B17): GetByID is called BEFORE
// Revoke so the audit row carries `user_id` and `broker_provider_id`
// alongside the grant `id`. Forensic queries become single-step. If the
// grant doesn't exist the lookup returns (nil, nil) and the detail
// records empty values; the storage Revoke is idempotent regardless.
func (s *GrantAdminService) RevokeBroker(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "GrantAdminService.RevokeBroker")
	defer span.End()
	span.SetAttributes(attribute.String("grant_id", id))

	if id == "" {
		err := domain.NewInvalidRequestError("id is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	grant, err := s.brokers.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("lookup broker grant: %w", err)
	}

	if err := s.brokers.Revoke(ctx, id); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("revoke broker grant: %w", err)
	}

	var userID, providerID string
	if grant != nil {
		userID = grant.UserID
		providerID = grant.BrokerProviderID
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionBrokerGrantRevokedAdmin,
			"admin", "", "",
			fmt.Sprintf("id=%s user_id=%s broker_provider_id=%s", id, userID, providerID),
		))
	}

	s.logger.InfoContext(ctx, "broker grant revoked",
		"grant_id", id,
		"user_id", userID,
		"broker_provider_id", providerID,
	)
	return nil
}
