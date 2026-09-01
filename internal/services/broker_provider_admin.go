package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// BrokerProviderAdminService implements input.BrokerProviderAdminPort over
// output.BrokerProviderStore. The admin layer never inspects
// ConfigData — the brokerproto adapter that owns the protocol validates the
// shape lazily at first vend.
type BrokerProviderAdminService struct {
	providers     output.BrokerProviderStore
	secretEncoder output.SecretEncoder
	audit         AuditRecorder
	logger        *slog.Logger
	tracer        trace.Tracer
}

var _ input.BrokerProviderAdminPort = (*BrokerProviderAdminService)(nil)

// BrokerProviderAdminServiceOpt configures optional BrokerProviderAdminService deps.
type BrokerProviderAdminServiceOpt func(*BrokerProviderAdminService)

// NewBrokerProviderAdminService constructs a BrokerProviderAdminService.
func NewBrokerProviderAdminService(
	providers output.BrokerProviderStore,
	obs *observability.Provider,
	auditSvc AuditRecorder,
	secretEncoder output.SecretEncoder,
	opts ...BrokerProviderAdminServiceOpt,
) *BrokerProviderAdminService {
	svc := &BrokerProviderAdminService{
		providers:     providers,
		secretEncoder: secretEncoder,
		audit:         auditSvc,
		logger:        obs.Logger,
		tracer:        obs.Tracer,
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

// List returns all BrokerProviders ordered by slug.
func (s *BrokerProviderAdminService) List(ctx context.Context) ([]*resource.BrokerProvider, error) {
	ctx, span := s.tracer.Start(ctx, "BrokerProviderAdminService.List")
	defer span.End()

	rows, err := s.providers.List(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list broker providers: %w", err)
	}
	return rows, nil
}

// GetByID returns the BrokerProvider with the given id.
func (s *BrokerProviderAdminService) GetByID(ctx context.Context, id string) (*resource.BrokerProvider, error) {
	ctx, span := s.tracer.Start(ctx, "BrokerProviderAdminService.GetByID")
	defer span.End()
	span.SetAttributes(attribute.String("id", id))

	p, err := s.providers.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return p, nil
}

// GetBySlug returns the BrokerProvider with the given slug.
func (s *BrokerProviderAdminService) GetBySlug(ctx context.Context, slug string) (*resource.BrokerProvider, error) {
	ctx, span := s.tracer.Start(ctx, "BrokerProviderAdminService.GetBySlug")
	defer span.End()
	span.SetAttributes(attribute.String("slug", slug))

	p, err := s.providers.GetBySlug(ctx, slug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return p, nil
}

// secretRefFields returns the config_data key names that hold secret
// references for the given protocol. The returned slice is nil when the
// protocol has no ref fields (api_key — secrets are env-resolved at vend
// time, not stored as refs in config_data).
func secretRefFields(protocol resource.Protocol) []string {
	switch protocol {
	case resource.ProtocolOAuth:
		return []string{"client_secret_ref"}
	case resource.ProtocolServiceAccount:
		return []string{"sa_key_ref"}
	default:
		return nil
	}
}

// jsonString returns the string value of a JSON-string RawMessage. An absent key
// or an explicit JSON null yields ("", nil) — treated as "not provided". A present
// value of any other type (number, bool, object, array) yields a non-nil error so
// the caller can reject the malformed input rather than silently treating a typo'd
// secret reference as absent (which would only surface much later, at vend).
func jsonString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("invalid JSON value: %w", err)
	}
	switch t := v.(type) {
	case nil:
		return "", nil // explicit JSON null == not provided
	case string:
		return t, nil
	default:
		return "", fmt.Errorf("expected a JSON string, got %T", v)
	}
}

// routeSecretFields runs each protocol secret field (secretRefFields) through the
// wired SecretEncoder and then enforces the post-encode raw-secret invariant.
//
// For each field it forwards BOTH what the operator provided — the reference
// (`<field>_ref`) and any raw value (`<field>`) — and lets the SecretEncoder
// decide the at-rest form (the env backend wants a ref and rejects a raw value
// with output.ErrSecretInputRejected; an encryptor-backed backend encrypts the
// raw value). A returned ciphertext is routed to the provider's
// EncSecretData/EncSecretBackend columns and BOTH the raw `<field>` and its
// `<field>_ref` are stripped from config_data; otherwise the returned ref is
// written to `<field>_ref`. A field with neither a ref nor a value is left
// untouched (the adapter reports a missing secret at vend, as before — no
// create-time rejection). Rejected input surfaces as a 400; an infrastructure
// failure propagates as-is (500).
//
// After routing, assertNoRawSecretsRemain catches a raw secret in any key that is
// NOT a routed secret field (e.g. a stray `*_password`).
func (s *BrokerProviderAdminService) routeSecretFields(ctx context.Context, p *resource.BrokerProvider) error {
	var configMap map[string]json.RawMessage
	if err := json.Unmarshal(p.ConfigData, &configMap); err != nil {
		return fmt.Errorf("unmarshal config_data for secret routing: %w", err)
	}
	mutated := false
	for _, refKey := range secretRefFields(p.Protocol) {
		field := strings.TrimSuffix(refKey, "_ref")
		ref, err := jsonString(configMap[refKey])
		if err != nil {
			return domain.NewInvalidRequestError(fmt.Sprintf("config_data field %q: %v", refKey, err))
		}
		value, err := jsonString(configMap[field])
		if err != nil {
			return domain.NewInvalidRequestError(fmt.Sprintf("config_data field %q: %v", field, err))
		}
		if ref == "" && value == "" {
			continue // nothing provided for this field
		}
		if ref != "" && value != "" {
			// Mutually exclusive — a literal value and a *_ref name for the same
			// field is ambiguous. Reject rather than let Encode silently prefer the
			// literal and drop the ref (symmetric with the OIDC config check).
			return domain.NewInvalidRequestError(fmt.Sprintf(
				"config_data fields %q and %q are mutually exclusive — set only one", field, refKey))
		}
		encoded, err := s.secretEncoder.Encode(ctx, output.GetSecretInputForBrokerProvider(p, value, ref, field))
		if err != nil {
			if errors.Is(err, output.ErrSecretInputRejected) {
				return domain.NewInvalidRequestError(err.Error())
			}
			return fmt.Errorf("encode secret for field %q: %w", field, err)
		}
		if len(encoded.Data) > 0 {
			// Encrypted-column path: the secret lives in EncSecretData; config_data
			// must carry neither the raw value nor a stale env reference.
			p.EncSecretData = encoded.Data
			p.EncSecretBackend = encoded.Backend
			delete(configMap, field)
			delete(configMap, refKey)
			mutated = true
		} else {
			// A ref (env path) now owns this secret — drop any stale encrypted
			// column so the Data→Ref read precedence can't silently return
			// the OLD secret at vend (rotation column→ref). Reached only when a ref
			// was supplied (value=="" here), so clearing is always correct; it is a
			// no-op on Create and on the env-only path (column never populated).
			if len(p.EncSecretData) > 0 {
				p.EncSecretData = nil
				p.EncSecretBackend = ""
			}
			if encoded.Ref != ref {
				enc, _ := json.Marshal(encoded.Ref)
				configMap[refKey] = json.RawMessage(enc)
				mutated = true
			}
			if value != "" {
				delete(configMap, field) // raw value consumed by Encode — never persist it
				mutated = true
			}
		}
	}
	// Only re-marshal when something changed, so an env-backend Encode (which
	// returns the ref unchanged and sees no raw value) leaves p.ConfigData verbatim.
	if mutated {
		remarshaled, err := json.Marshal(configMap)
		if err != nil {
			return fmt.Errorf("re-marshal config_data after secret routing: %w", err)
		}
		p.ConfigData = remarshaled
	}
	return assertNoRawSecretsRemain(configMap)
}

// Create inserts a new BrokerProvider after slug normalization + protocol
// validation.
func (s *BrokerProviderAdminService) Create(ctx context.Context, p *resource.BrokerProvider) error {
	ctx, span := s.tracer.Start(ctx, "BrokerProviderAdminService.Create")
	defer span.End()
	span.SetAttributes(attribute.String("slug", p.Slug))

	if p.ID != "" {
		err := domain.NewInvalidRequestError("id must not be supplied on create")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	canonicalSlug, err := resource.NormalizeSlug(p.Slug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	p.Slug = canonicalSlug

	applyBrokerProviderDefaults(p)
	if err := validateBrokerProviderStructural(p); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	// Pre-check for slug conflicts so the wire-level error is a clean 409
	// rather than a 500 from the underlying UNIQUE-constraint driver error.
	// See ResourceAdminService.Create for the race-window note.
	if err := s.assertSlugAvailable(ctx, p.Slug, ""); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	now := time.Now().UTC()
	p.ID = crypto.GenerateRandomString(16)
	p.CreatedAt = now
	p.UpdatedAt = now

	// No transaction needed: routeSecretFields is in-memory (encode → mutate p)
	// and providers.Create is a single INSERT, so the row commits atomically on
	// its own. The encrypted secret lives in a column of this same row (not a
	// separate write), so there is no orphan to guard against.
	if err := s.routeSecretFields(ctx, p); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if err := s.providers.Create(ctx, p); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionBrokerProviderCreated,
			"admin", "", "",
			fmt.Sprintf("id=%s slug=%s", p.ID, p.Slug),
		))
	}

	s.logger.InfoContext(ctx, "broker provider created",
		"id", p.ID, "slug", p.Slug, "protocol", string(p.Protocol))
	return nil
}

// Patch applies a partial update per BrokerProviderPatch semantics.
func (s *BrokerProviderAdminService) Patch(ctx context.Context, id string, patch input.BrokerProviderPatch) (*resource.BrokerProvider, error) {
	ctx, span := s.tracer.Start(ctx, "BrokerProviderAdminService.Patch")
	defer span.End()
	span.SetAttributes(attribute.String("id", id))

	if id == "" {
		err := domain.NewInvalidRequestError("id is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	p, err := s.providers.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	var touched []string
	if patch.Slug != nil {
		canonical, err := resource.NormalizeSlug(*patch.Slug)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
		p.Slug = canonical
		touched = append(touched, "slug")
	}
	if patch.DisplayName != nil {
		p.DisplayName = *patch.DisplayName
		touched = append(touched, "display_name")
	}
	if patch.Protocol != nil {
		p.Protocol = *patch.Protocol
		touched = append(touched, "protocol")
	}
	if patch.ConfigData != nil {
		p.ConfigData = []byte(*patch.ConfigData)
		touched = append(touched, "config_data")
	}

	// Empty patch: see ResourceAdminService.Patch for the rationale.
	if len(touched) == 0 {
		return p, nil
	}

	applyBrokerProviderDefaults(p)
	if err := validateBrokerProviderStructural(p); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if patch.Slug != nil {
		if err := s.assertSlugAvailable(ctx, p.Slug, p.ID); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
	}

	p.UpdatedAt = time.Now().UTC()

	// No transaction needed: routeSecretFields is in-memory and providers.Update
	// is a single UPDATE. Route the secret fields only when config_data was
	// supplied in this patch; otherwise the existing (already-validated)
	// config_data is left untouched.
	if patch.ConfigData != nil {
		if err := s.routeSecretFields(ctx, p); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
	}
	if err := s.providers.Update(ctx, p); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionBrokerProviderPatched,
			"admin", "", "",
			fmt.Sprintf("id=%s slug=%s fields=%s", p.ID, p.Slug, strings.Join(touched, ",")),
		))
	}

	s.logger.InfoContext(ctx, "broker provider patched",
		"id", p.ID, "slug", p.Slug, "fields", strings.Join(touched, ","))
	return p, nil
}

// Delete removes the BrokerProvider by id.
func (s *BrokerProviderAdminService) Delete(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "BrokerProviderAdminService.Delete")
	defer span.End()
	span.SetAttributes(attribute.String("id", id))

	if id == "" {
		err := domain.NewInvalidRequestError("id is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if err := s.providers.Delete(ctx, id); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionBrokerProviderDeleted,
			"admin", "", "",
			fmt.Sprintf("id=%s", id),
		))
	}

	s.logger.InfoContext(ctx, "broker provider deleted", "id", id)
	return nil
}

// assertSlugAvailable returns a CodeConflict domain error if a different
// BrokerProvider row already holds the given slug. excludeID is the id of
// the row being patched (so a no-op slug write succeeds); pass "" on
// Create. TOCTOU race window — see ResourceAdminService.assertSlugAvailable
// for the rationale.
func (s *BrokerProviderAdminService) assertSlugAvailable(ctx context.Context, slug, excludeID string) error {
	existing, err := s.providers.GetBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, domain.ErrResourceNotFound) {
			return nil
		}
		return fmt.Errorf("lookup broker provider by slug %q: %w", slug, err)
	}
	if existing.ID == excludeID {
		return nil
	}
	return domain.NewConflictError(fmt.Sprintf("slug %q is already in use", slug))
}

// applyBrokerProviderDefaults fills in fields whose absence the admin
// layer accepts as "use the default". Currently: empty ConfigData
// becomes the JSON empty object so the brokerproto adapter never has to
// handle nil bytes. Mutates the passed-in pointer; pure validation lives
// in validateBrokerProvider.
//
// Split out from validateBrokerProvider so the validator stays
// side-effect-free — audit finding D8/B16.
func applyBrokerProviderDefaults(p *resource.BrokerProvider) {
	if len(p.ConfigData) == 0 {
		p.ConfigData = []byte("{}")
	}
}

// rawSecretKeyPattern matches top-level config_data keys that end with
// "_secret" or "_password" (case-insensitive). Such fields conventionally
// hold raw credential values and should never be persisted in the DB —
// the brokerproto adapter convention is to use a "*_ref" sibling
// (e.g. client_secret_ref) that names an environment variable resolved at
// vend-time. See the data model
//
// Note that the pattern intentionally requires a `_` prefix on the
// danger suffix, so legitimate keys like `secret_validity_seconds` or
// `password_policy` (no `_secret`/`_password` suffix) are unaffected.
// `client_secret_ref` ends with `_ref`, not `_secret`, so it also passes.
var rawSecretKeyPattern = regexp.MustCompile(`(?i)_(secret|password)$`)

// Create/Patch validate in two phases: validateBrokerProviderStructural runs
// up front (display name, protocol, config_data shape), and assertNoRawSecretsRemain
// runs AFTER the SecretEncoder routing (inside routeSecretFields), so a routed raw
// value is consumed and stripped before the raw-secret guard checks.
//
// validateBrokerProviderStructural enforces display name presence, protocol
// membership, and that ConfigData is a syntactically valid JSON object. The
// raw-secret guard (assertNoRawSecretsRemain) runs separately, after the
// SecretEncoder routing (see routeSecretFields).
//
// Pure: does not mutate p. Defaults are applied separately by
// applyBrokerProviderDefaults — call that first if defaults are desired.
func validateBrokerProviderStructural(p *resource.BrokerProvider) error {
	if p.DisplayName == "" {
		return domain.NewInvalidRequestError("display_name is required")
	}
	switch p.Protocol {
	case resource.ProtocolOAuth, resource.ProtocolAPIKey, resource.ProtocolServiceAccount:
		// ok
	default:
		return domain.NewInvalidRequestError(fmt.Sprintf("protocol must be oauth, api_key, or service_account, got %q", p.Protocol))
	}
	if len(p.ConfigData) == 0 {
		// Caller must run applyBrokerProviderDefaults first if they want
		// the empty-object default. A bare validate call on empty bytes
		// is rejected so this function stays pure.
		return domain.NewInvalidRequestError("config_data must not be empty (call applyBrokerProviderDefaults first)")
	}
	// Reject non-object payloads (null, arrays, strings, numbers, booleans)
	// AND syntactically invalid JSON. We need both checks because
	// json.Unmarshal accepts the literal `null` for any pointer/map
	// destination (treats it as "leave at zero value"). Validating the
	// leading non-whitespace byte rules that out; the Unmarshal call covers
	// well-formedness + non-object types.
	trimmed := bytes.TrimSpace(p.ConfigData)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return domain.NewInvalidRequestError("config_data must be a JSON object")
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(p.ConfigData, &probe); err != nil {
		return domain.NewInvalidRequestError("config_data must be a valid JSON object")
	}
	return nil
}

// assertNoRawSecretsRemain guards against literal credential values persisted
// in config_data. It rejects any top-level key matching rawSecretKeyPattern
// (*_secret or *_password) whose value is a non-empty JSON string.
//
// Defense-in-depth — audit finding B12. The brokerproto-adapter convention is
// to reference secrets via a *_ref sibling (e.g. client_secret_ref) that names
// an environment variable resolved at vend time; persisting a literal
// credential value in the DB defeats that pattern.
func assertNoRawSecretsRemain(probe map[string]json.RawMessage) error {
	for key, raw := range probe {
		if !rawSecretKeyPattern.MatchString(key) {
			continue
		}
		// Only reject when the value is a non-empty JSON string. Booleans,
		// numbers, objects, arrays under these keys are unusual but not
		// the credential-leak pattern this rule targets.
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			continue
		}
		if s == "" {
			continue
		}
		return domain.NewInvalidRequestError(fmt.Sprintf(
			"config_data.%s must not contain a literal value; use the *_ref convention "+
				"(e.g. %s_ref: \"ENV_VAR_NAME\") to resolve secrets at vend time",
			key, key,
		))
	}
	return nil
}
