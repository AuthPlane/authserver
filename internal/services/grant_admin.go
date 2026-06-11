package services

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
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
// matching live Mint issuances per the data model
//
// Ordering: GetByID is called BEFORE Revoke so the (user, client,
// resource) triple is captured pre-mutation; the storage Revoke
// returns no row data and Get filters revoked rows out, so capturing
// the triple after the revocation isn't possible against the active
// store contract.
//
// Cascade-failure handling: if RevokeFamily fails after the grant has
// been revoked, the system enters a partial-success state — grant gone,
// some live tokens linger until expiry. The grant revocation is the
// load-bearing security action (no NEW tokens can be minted), so we log
// loudly + audit revoked_issuances=0 and return nil. Alerting on
// revoked_issuances=0 in the audit log catches the case at runtime.
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

	if s.audit != nil {
		detail := fmt.Sprintf("id=%s user_id=%s client_id=%s resource_id=%s revoked_issuances=%d",
			id, userID, clientID, resourceID, revokedIssuances)
		if cascadeFailed {
			detail += " cascade=failed"
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
	)
	return nil
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
