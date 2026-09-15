package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ input.PRMetadataPort = (*PRMetadataService)(nil)

// ResourceResolver resolves one Resource by slug or URI. Satisfied by
// *ResourceRegistry; narrowed to the single method this service needs so the
// dependency is honest about its surface.
type ResourceResolver interface {
	Resolve(ctx context.Context, slugOrURI string) (*resource.Resource, error)
}

// PRMetadataService assembles OAuth 2.0 Protected Resource Metadata (RFC 9728)
// for the Resources registered with this authorization server.
//
// Why the AS serves this at all, when RFC 9728 §3.1 derives the metadata URL
// from the resource identifier's own host: an MCP server is frequently a
// process the operator cannot add a /.well-known route to — a managed gateway,
// a third-party proxy, a framework that owns its routing. The MCP authorization
// spec has clients take the metadata URL from the resource_metadata parameter
// of the WWW-Authenticate challenge, and that parameter may point anywhere. An
// AS-hosted document is therefore reachable for any Resource whose 401 names
// it, while a Resource sharing the AS's origin is additionally reachable at the
// exact path RFC 9728 tells a client to construct.
type PRMetadataService struct {
	issuer    output.IssuerProvider
	resources ResourceResolver
	logger    *slog.Logger
	tracer    trace.Tracer
}

// NewPRMetadataService wires the Protected Resource Metadata assembler.
func NewPRMetadataService(
	issuer output.IssuerProvider,
	resources ResourceResolver,
	obs *observability.Provider,
) *PRMetadataService {
	return &PRMetadataService{
		issuer:    issuer,
		resources: resources,
		// Callers pass an already component-scoped provider, so don't re-tag.
		logger: obs.Logger,
		tracer: obs.Tracer,
	}
}

// Metadata resolves ref to a registered Resource and returns its RFC 9728
// document.
//
// Resolution order for a non-empty ref, and the reason for it:
//
//  1. The RFC 9728 §3.1 reconstruction — issuer origin + "/" + ref. This is the
//     URL a client builds on its own from a resource identifier hosted on this
//     origin, so it must win: a client that constructed the path deserves the
//     Resource it named, never one that merely happens to carry that slug.
//  2. ref as a Resource slug. This is the AS-hosted form, reachable only when a
//     401 challenge points at it, and the only form available to a Resource
//     living on a different host.
//
// Returns domain.ErrResourceNotFound when neither matches.
func (s *PRMetadataService) Metadata(ctx context.Context, ref string) (*input.ProtectedResourceMetadata, error) {
	ctx, span := s.tracer.Start(ctx, "PRMetadataService.Metadata")
	defer span.End()
	// Truncated: ref is attacker-controlled and the server sets no
	// MaxHeaderBytes, so an unbounded value would ship verbatim to the trace
	// backend. 256 bytes is far beyond any legitimate slug or resource path.
	span.SetAttributes(attribute.String("ref", truncateForSpan(ref, 256)))

	issuer, err := s.issuer.Issuer(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("resolve issuer: %w", err)
	}

	// A ref that is not valid UTF-8, or carries a NUL, can never name a
	// registered resource: slugs are [a-z0-9-] and URIs are absolute http(s)
	// URLs. Rejecting here rather than letting it reach the store matters
	// because Postgres refuses such bytes as a text parameter (SQLSTATE 22021),
	// which turned an anonymous request into two failed round-trips, three
	// ERROR log lines carrying the attacker's bytes, two error spans and a 500
	// — for what is a client input error deserving a 404.
	if !utf8.ValidString(ref) || strings.ContainsRune(ref, 0) {
		span.SetStatus(codes.Error, "malformed ref")
		return nil, domain.ErrResourceNotFound
	}

	res, err := s.resolve(ctx, issuer, ref)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// resource is the one REQUIRED member of RFC 9728 §2, and §3.3 has the
	// client compare it against the identifier it asked about. A Resource
	// registered without a URI (permitted — the slug is then its canonical
	// identifier) has nothing to put there, so emitting the document would
	// hand a conformant client something it must reject. 404 is the honest
	// answer: this Resource has no metadata document.
	if res.URI == "" {
		s.logger.WarnContext(ctx,
			"protected resource metadata: resource has no URI, so no RFC 9728 document can be built; serving 404",
			"slug", res.Slug,
		)
		span.SetStatus(codes.Error, "resource has no URI")
		return nil, domain.ErrResourceNotFound
	}

	scopes := make([]string, 0, len(res.Scopes))
	for _, sc := range res.Scopes {
		scopes = append(scopes, sc.Name)
	}

	return &input.ProtectedResourceMetadata{
		// Verbatim: a client compares this against the identifier it asked
		// about, so normalization here would break that comparison.
		Resource:             res.URI,
		AuthorizationServers: []string{issuer},
		ScopesSupported:      scopes,
		// The MCP spec mandates the Authorization header and forbids tokens in
		// the query string, so "header" is the only honest answer.
		BearerMethodsSupported: []string{"header"},
		ResourceName:           res.DisplayName,
	}, nil
}

// resolve maps ref onto a registered Resource. See Metadata for the ordering
// rationale.
func (s *PRMetadataService) resolve(ctx context.Context, issuer, ref string) (*resource.Resource, error) {
	if ref == "" {
		// The bare well-known path addresses a Resource whose identifier is
		// this origin exactly.
		return s.lookup(ctx, issuer)
	}

	// 1. RFC 9728 §3.1 reconstruction.
	if res, err := s.lookup(ctx, strings.TrimSuffix(issuer, "/")+"/"+ref); err == nil {
		return res, nil
	}

	// 2. Slug.
	return s.lookup(ctx, ref)
}

// lookup wraps Resolve, collapsing an ambiguous match to not-found.
//
// Ambiguity means two Resources answer to the same slug-or-URI, which is an
// operator misconfiguration rather than anything a client can act on. Reporting
// it as not-found keeps the endpoint from becoming a probe for how the registry
// is configured, and the warning below is where an operator finds out.
func (s *PRMetadataService) lookup(ctx context.Context, ref string) (*resource.Resource, error) {
	res, err := s.resources.Resolve(ctx, ref)
	switch {
	case err == nil:
		return res, nil
	case errors.Is(err, domain.ErrAmbiguousResource):
		s.logger.WarnContext(ctx,
			"protected resource metadata: reference matches more than one resource; serving 404",
			"ref", ref,
		)
		return nil, domain.ErrResourceNotFound
	default:
		return nil, err
	}
}

// truncateForSpan bounds an attacker-controlled value before it becomes a span
// attribute. No AttributeValueLengthLimit is configured on the tracer provider,
// so without this the full string reaches the collector.
func truncateForSpan(v string, max int) string {
	if len(v) <= max {
		return v
	}
	return v[:max] + "…"
}
