package services

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/scope"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/domain/xaa"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ input.XAAPolicyPort = (*XAAPolicyService)(nil)

// XAAPolicyService manages XAA policies and evaluates them during the
// jwt-bearer grant flow.
type XAAPolicyService struct {
	policyStore output.XAAPolicyStore
	idpStore    output.IDPStore
	logger      *slog.Logger
	tracer      trace.Tracer
	metrics     *observability.Metrics
	audit       AuditRecorder
}

// NewXAAPolicyService creates a new XAA policy administration and evaluation service.
func NewXAAPolicyService(
	policyStore output.XAAPolicyStore,
	idpStore output.IDPStore,
	obs *observability.Provider,
	auditRec AuditRecorder,
) *XAAPolicyService {
	return &XAAPolicyService{
		policyStore: policyStore,
		idpStore:    idpStore,
		logger:      obs.Logger.With("component", "xaa_policy"),
		tracer:      obs.Tracer,
		metrics:     obs.Metrics,
		audit:       auditRec,
	}
}

// CreatePolicy creates a new XAA policy.
func (s *XAAPolicyService) CreatePolicy(ctx context.Context, req input.CreatePolicyRequest) (*xaa.Policy, error) {
	ctx, span := s.tracer.Start(ctx, "XAAPolicyService.CreatePolicy")
	defer span.End()

	if req.Name == "" || req.IDPID == "" {
		return nil, fmt.Errorf("name and idp_id are required")
	}

	// Verify IdP exists.
	if _, err := s.idpStore.GetByID(ctx, req.IDPID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "idp not found")
		return nil, fmt.Errorf("idp %q: %w", req.IDPID, domain.ErrIDPNotFound)
	}

	now := time.Now().UTC()
	p := xaa.Policy{
		ID:        crypto.GenerateRandomString(16),
		Name:      req.Name,
		IDPID:     req.IDPID,
		ClientIDs: req.ClientIDs,
		Scopes:    req.Scopes,
		Resources: req.Resources,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.policyStore.Save(ctx, p); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("save policy: %w", err)
	}

	s.logger.InfoContext(ctx, "xaa policy created",
		"policy_id", p.ID,
		"name", p.Name,
		"idp_id", p.IDPID,
	)

	return &p, nil
}

// GetPolicy retrieves a policy by ID.
func (s *XAAPolicyService) GetPolicy(ctx context.Context, id string) (*xaa.Policy, error) {
	ctx, span := s.tracer.Start(ctx, "XAAPolicyService.GetPolicy")
	defer span.End()

	p, err := s.policyStore.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return p, nil
}

// ListPolicies returns policies, optionally filtered by IdP ID.
func (s *XAAPolicyService) ListPolicies(ctx context.Context, idpID string) ([]xaa.Policy, error) {
	ctx, span := s.tracer.Start(ctx, "XAAPolicyService.ListPolicies")
	defer span.End()

	var policies []xaa.Policy
	var err error
	if idpID != "" {
		policies, err = s.policyStore.ListByIDP(ctx, idpID)
	} else {
		policies, err = s.policyStore.List(ctx)
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return policies, nil
}

// UpdatePolicy partially updates a policy.
func (s *XAAPolicyService) UpdatePolicy(ctx context.Context, id string, req input.UpdatePolicyRequest) (*xaa.Policy, error) {
	ctx, span := s.tracer.Start(ctx, "XAAPolicyService.UpdatePolicy")
	defer span.End()

	p, err := s.policyStore.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if req.Name != nil {
		p.Name = *req.Name
	}
	if req.Enabled != nil {
		p.Enabled = *req.Enabled
	}
	if req.ClientIDs != nil {
		p.ClientIDs = req.ClientIDs
	}
	if req.Scopes != nil {
		p.Scopes = req.Scopes
	}
	if req.Resources != nil {
		p.Resources = req.Resources
	}
	p.UpdatedAt = time.Now().UTC()

	if err := s.policyStore.Save(ctx, *p); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("update policy: %w", err)
	}

	s.logger.InfoContext(ctx, "xaa policy updated", "policy_id", id)
	return p, nil
}

// DeletePolicy removes a policy by ID.
func (s *XAAPolicyService) DeletePolicy(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "XAAPolicyService.DeletePolicy")
	defer span.End()

	if err := s.policyStore.Delete(ctx, id); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	s.logger.InfoContext(ctx, "xaa policy deleted", "policy_id", id)
	return nil
}

// PolicyDecision is the result of a policy evaluation.
type PolicyDecision struct {
	Allowed        bool
	EffectiveScope scope.Set
}

// EvaluatePolicy checks whether an assertion is permitted by any enabled
// policy for the IdP, and returns the effective scopes.
func (s *XAAPolicyService) EvaluatePolicy(
	ctx context.Context,
	idpID string,
	assertion *token.IdentityAssertion,
	c *client.Client,
	requestedScopes scope.Set,
	effectiveResource string,
) (*PolicyDecision, error) {
	ctx, span := s.tracer.Start(ctx, "XAAPolicyService.EvaluatePolicy")
	defer span.End()

	policies, err := s.policyStore.ListByIDP(ctx, idpID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list policies for idp %q: %w", idpID, err)
	}

	// Check each enabled policy for a match.
	for i := range policies {
		p := &policies[i]
		if !p.Enabled {
			continue
		}

		// Check client_id constraint.
		if len(p.ClientIDs) > 0 && !contains(p.ClientIDs, assertion.ClientID) {
			continue
		}

		// Check resource constraint against the effective resource selected by
		// the grant (derived from req.Resource or assertion.Resource).
		if len(p.Resources) > 0 && !contains(p.Resources, effectiveResource) {
			continue
		}

		// Compute effective scopes against the policy's scope constraint.
		// Semantics: nil Scopes = no restriction (caller's full request passes).
		//            non-nil but empty Scopes = deny-all (skip this policy).
		//            non-empty Scopes = upper bound; a request that exceeds it
		//                               does NOT match this policy — try next.
		//
		// Pre-fix this used silent intersection (Intersect) and let a policy
		// that covered ONE requested scope match and return only that scope.
		// That inverted operator intent: a [read] policy would silently
		// match a [read, write] request and emit a narrowed [read] token,
		// hiding misconfiguration. Mirrors the MED 4 fail-closed correction
		// in client_credentials and jwt_bearer.
		effectiveScopes := requestedScopes
		if p.Scopes != nil {
			if len(p.Scopes) == 0 {
				// Explicit empty list: no scopes permitted by this policy.
				continue
			}
			policyScopes := scope.Parse(joinScopes(p.Scopes))
			if !requestedScopes.IsEmpty() {
				if !requestedScopes.IsSubset(policyScopes) {
					// Policy max can't satisfy the full request — try next.
					continue
				}
				// requestedScopes stays the effective set (already assigned).
			} else {
				// No explicit request: take the policy's max as effective.
				effectiveScopes = policyScopes
			}
		}

		s.metrics.XAAPolicyEvaluationTotal.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("result", "allowed"),
		))
		return &PolicyDecision{
			Allowed:        true,
			EffectiveScope: effectiveScopes,
		}, nil
	}

	// No matching policy found.
	span.SetStatus(codes.Error, "no matching policy")
	s.metrics.XAAPolicyEvaluationTotal.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("result", "denied"),
	))
	return nil, domain.ErrAssertionPolicyDenied
}

// contains checks whether slice ss contains string s.
func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// joinScopes joins a string slice into a space-separated scope string.
func joinScopes(scopes []string) string {
	result := ""
	for i, s := range scopes {
		if i > 0 {
			result += " "
		}
		result += s
	}
	return result
}
