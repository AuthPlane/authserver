package services

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/brokerproto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// mockAuditRecorder captures audit.Event values for cross-package tests
// in `package services` (broker_provider_admin_test.go, grant_admin_test.go,
// issuance_admin_test.go, resource_admin_test.go). Defined here so the
// services package keeps a single test-side audit recorder.
type mockAuditRecorder struct {
	events []audit.Event
}

func (m *mockAuditRecorder) Record(_ context.Context, e audit.Event) {
	m.events = append(m.events, e)
}

// --- Mocks specific to ConnectService ---

type mockConnectPendingStateStore struct {
	mu        sync.Mutex
	rows      map[string]*resource.ConnectPendingState
	insertErr error
	consumeFn func(id string) (*resource.ConnectPendingState, error)
}

func newMockPendingStateStore() *mockConnectPendingStateStore {
	return &mockConnectPendingStateStore{rows: make(map[string]*resource.ConnectPendingState)}
}

func (m *mockConnectPendingStateStore) Insert(_ context.Context, s *resource.ConnectPendingState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.insertErr != nil {
		return m.insertErr
	}
	m.rows[s.ID] = s
	return nil
}

func (m *mockConnectPendingStateStore) Consume(_ context.Context, id string) (*resource.ConnectPendingState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.consumeFn != nil {
		return m.consumeFn(id)
	}
	row, ok := m.rows[id]
	if !ok {
		return nil, domain.ErrPendingStateNotFound
	}
	delete(m.rows, id)
	return row, nil
}

func (m *mockConnectPendingStateStore) PurgeExpired(_ context.Context, _ time.Time) (int, error) {
	return 0, nil
}

// configurableConnectAdapter is a stub BrokerProtocol used by ConnectService
// tests. Per-method behavior is overridable; defaults populate sensible
// "happy path" pending state and credential bytes.
type configurableConnectAdapter struct {
	name                  string
	buildErr              error
	buildPending          *resource.ConnectPendingState
	buildURL              string
	handleErr             error
	handleCred            []byte
	handleScopes          []string
	revokeErr             error
	revokeCalls           int
	mu                    sync.Mutex
	lastBuildScope        []string
	lastCallbackURL       string
	lastHandleCallbackURL string
}

func (a *configurableConnectAdapter) Name() string {
	if a.name == "" {
		return "oauth"
	}
	return a.name
}

func (a *configurableConnectAdapter) BuildConnectURL(
	_ context.Context, _ *resource.BrokerProvider, _ *resource.Resource,
	_, _, callbackURL string, scopes []string,
) (string, *resource.ConnectPendingState, error) {
	a.mu.Lock()
	a.lastBuildScope = append([]string(nil), scopes...)
	a.lastCallbackURL = callbackURL
	a.mu.Unlock()
	if a.buildErr != nil {
		return "", nil, a.buildErr
	}
	pending := a.buildPending
	if pending == nil {
		pending = &resource.ConnectPendingState{
			CodeVerifier: "test-verifier",
		}
	}
	url := a.buildURL
	if url == "" {
		url = "https://upstream.example.com/authorize?state=adapter-state&client_id=cid"
	}
	return url, pending, nil
}

func (a *configurableConnectAdapter) HandleCallback(
	_ context.Context, _ *resource.BrokerProvider, _ *resource.Resource,
	_, callbackURL string, _ *resource.ConnectPendingState,
) ([]byte, []string, error) {
	a.mu.Lock()
	a.lastHandleCallbackURL = callbackURL
	a.mu.Unlock()
	if a.handleErr != nil {
		return nil, nil, a.handleErr
	}
	cred := a.handleCred
	if cred == nil {
		cred = []byte(`{"refresh_token":"upstream-refresh"}`)
	}
	scopes := a.handleScopes
	if scopes == nil {
		scopes = []string{"repo", "read:user"}
	}
	return cred, scopes, nil
}

func (a *configurableConnectAdapter) Vend(
	context.Context, *resource.BrokerProvider, *resource.Resource, []byte, []string,
) (string, int, []byte, error) {
	return "", 0, nil, errors.New("not used by ConnectService")
}

func (a *configurableConnectAdapter) Revoke(
	context.Context, *resource.BrokerProvider, []byte,
) error {
	a.mu.Lock()
	a.revokeCalls++
	a.mu.Unlock()
	return a.revokeErr
}

// --- Test fixtures ---

const (
	testUserID    = "user-1"
	testProvSlug  = "github"
	testProvID    = "bp-github-1"
	testResSlug   = "github-repo"
	testResID     = "res-github-repo-1"
	testReturnURL = "https://app.example.com/back"
)

func githubProvider() *resource.BrokerProvider {
	return &resource.BrokerProvider{
		ID:       testProvID,
		Slug:     testProvSlug,
		Protocol: resource.ProtocolOAuth,
	}
}

func githubBrokerResource() *resource.Resource {
	return &resource.Resource{
		ID:               testResID,
		Slug:             testResSlug,
		BackendKind:      resource.BackendBroker,
		BrokerProviderID: testProvID,
		Policy: resource.Policy{
			Connect: resource.ConnectPolicy{
				AllowedReturnURLs: []string{testReturnURL},
			},
		},
		Scopes: []resource.Scope{{Name: "repo", Upstream: "repo"}},
	}
}

func newConnectFixture(
	t *testing.T,
	provStore *mockBrokerProviderStore,
	resStore *mockResourceStore,
	grants *mockBrokerGrantStore,
	adapter output.BrokerProtocol,
	allowedGlobalReturn []string,
) (*ConnectService, *mockConnectPendingStateStore, *captureAuditRecorder) {
	t.Helper()
	// Provide a default List that surfaces a single Broker anchor — the
	// connect_pending_states FK requires a non-null resource_id, and
	// ConnectService falls back to "any Broker resource for this provider"
	// when ?resource= is omitted. Tests that need a different anchor set
	// resStore.listFn explicitly.
	if resStore.listFn == nil {
		resStore.listFn = func(filter output.ResourceFilter) ([]*resource.Resource, error) {
			if filter.BackendKind == resource.BackendBroker && filter.BrokerProviderID == testProvID {
				return []*resource.Resource{githubBrokerResource()}, nil
			}
			return nil, nil
		}
	}
	// CompleteConnect resolves the pending state's ResourceID via
	// registry.GetWithProvider; provide a default getByIDFn so tests that
	// don't seed a pending resource still round-trip cleanly.
	if resStore.getByIDFn == nil {
		resStore.getByIDFn = func(id string) (*resource.Resource, error) {
			if id == "" {
				return nil, nil
			}
			return githubBrokerResource(), nil
		}
	}
	registry := NewResourceRegistry(resStore, provStore, observability.NewNoop())
	pending := newMockPendingStateStore()
	bp := brokerproto.NewRegistry()
	if adapter != nil {
		if err := bp.Register(adapter); err != nil {
			t.Fatalf("register stub adapter: %v", err)
		}
	}
	enc := &mockDataEncryptor{driverName: "mock"}
	rec := &captureAuditRecorder{}
	svc := NewConnectService(
		registry, resStore, provStore, grants, pending, bp, enc,
		static.NewConnectStateConfigProvider([]byte("test-state-secret-32-bytes!!!!!!")),
		static.NewIssuerProvider("https://as.test"),
		static.NewConnectConfigProvider(output.ConnectConfig{
			RedirectBaseURL:   "https://as.test",
			AllowedReturnURLs: allowedGlobalReturn,
		}),
		observability.NewNoop(), rec,
	)
	return svc, pending, rec
}

// failingConnectConfigProvider always errors, to assert return-URL validation
// fails closed (deny) on a config-resolution error rather than allowing the URL.
type failingConnectConfigProvider struct{ err error }

func (p failingConnectConfigProvider) Config(context.Context) (output.ConnectConfig, error) {
	return output.ConnectConfig{}, p.err
}

func TestConnectService_StartConnect_ConfigError_FailsClosed(t *testing.T) {
	// A connect-config resolution failure must abort StartConnect with the
	// wrapped error rather than proceeding to sign state / build the upstream
	// URL (fail closed). StartConnect resolves the config once, up front.
	wantErr := errors.New("connect config unavailable")
	provider := githubProvider()
	provStore := &mockBrokerProviderStore{
		getByIDFn: func(string) (*resource.BrokerProvider, error) { return provider, nil },
		getBySlug: func(string) (*resource.BrokerProvider, error) { return provider, nil },
	}
	svc, _, _ := newConnectFixture(t, provStore, &mockResourceStore{}, &mockBrokerGrantStore{},
		&configurableConnectAdapter{}, []string{testReturnURL})
	svc.connectConfig = failingConnectConfigProvider{err: wantErr}

	if _, err := svc.StartConnect(context.Background(), testUserID, testProvSlug, "", testReturnURL); err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("StartConnect: expected error wrapping %v on config failure, got %v", wantErr, err)
	}
}

// failingConnectStateConfigProvider always errors, to assert the connect-state
// signing path propagates a config-resolution error rather than signing or
// verifying with no key.
type failingConnectStateConfigProvider struct{ err error }

func (p failingConnectStateConfigProvider) Config(context.Context) (output.ConnectStateConfig, error) {
	return output.ConnectStateConfig{}, p.err
}

// emptyKeyConnectStateConfigProvider returns a config with no key, to assert the
// defensive empty-key guard rejects signing/verification under an alternate
// provider.
type emptyKeyConnectStateConfigProvider struct{}

func (emptyKeyConnectStateConfigProvider) Config(context.Context) (output.ConnectStateConfig, error) {
	return output.ConnectStateConfig{}, nil
}

func TestConnectService_StateToken_ConfigError_Propagates(t *testing.T) {
	wantErr := errors.New("state config unavailable")
	svc := &ConnectService{stateConfig: failingConnectStateConfigProvider{err: wantErr}}

	if _, err := svc.generateStateToken(context.Background(), "u", "p", "r"); err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("generateStateToken: expected error wrapping %v, got %v", wantErr, err)
	}
	if _, err := svc.verifyStateToken(context.Background(), "id.sig", "u", "p", "r"); err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("verifyStateToken: expected error wrapping %v, got %v", wantErr, err)
	}
}

func TestConnectService_StateToken_EmptyKey_Rejected(t *testing.T) {
	svc := &ConnectService{stateConfig: emptyKeyConnectStateConfigProvider{}}

	if _, err := svc.generateStateToken(context.Background(), "u", "p", "r"); err == nil {
		t.Fatal("generateStateToken: expected error on empty key, got nil")
	}
	if _, err := svc.verifyStateToken(context.Background(), "id.sig", "u", "p", "r"); err == nil {
		t.Fatal("verifyStateToken: expected error on empty key, got nil")
	}
}

// --- StartConnect ---

func TestConnectService_StartConnect_HappyPath(t *testing.T) {
	provStore := &mockBrokerProviderStore{
		getBySlug: func(slug string) (*resource.BrokerProvider, error) {
			if slug != testProvSlug {
				t.Fatalf("provider lookup got %q", slug)
			}
			return githubProvider(), nil
		},
	}
	resStore := &mockResourceStore{
		resolveFn: func(slugOrURI string) ([]*resource.Resource, error) {
			if slugOrURI != testResSlug {
				t.Fatalf("resource resolve got %q", slugOrURI)
			}
			return []*resource.Resource{githubBrokerResource()}, nil
		},
	}
	adapter := &configurableConnectAdapter{}
	svc, pending, _ := newConnectFixture(t, provStore, resStore, &mockBrokerGrantStore{}, adapter, nil)

	url, err := svc.StartConnect(context.Background(), testUserID, testProvSlug, testResSlug, testReturnURL)
	if err != nil {
		t.Fatalf("StartConnect: %v", err)
	}
	if !strings.HasPrefix(url, "https://upstream.example.com/authorize?") {
		t.Errorf("upstream URL = %q, want upstream prefix", url)
	}
	if !strings.Contains(url, "state=") {
		t.Errorf("upstream URL %q missing rebound state param", url)
	}

	pending.mu.Lock()
	defer pending.mu.Unlock()
	if len(pending.rows) != 1 {
		t.Fatalf("pending rows = %d, want 1", len(pending.rows))
	}
	for id, row := range pending.rows {
		if row.UserID != testUserID {
			t.Errorf("pending UserID = %q", row.UserID)
		}
		if row.ProviderID != testProvID {
			t.Errorf("pending ProviderID = %q", row.ProviderID)
		}
		if row.ResourceID != testResID {
			t.Errorf("pending ResourceID = %q", row.ResourceID)
		}
		if row.ReturnURL != testReturnURL {
			t.Errorf("pending ReturnURL = %q", row.ReturnURL)
		}
		if row.ID != id {
			t.Errorf("pending ID mismatch")
		}
	}
}

func TestConnectService_StartConnect_ResourceScopedReturnURL_Mismatch(t *testing.T) {
	provStore := &mockBrokerProviderStore{
		getBySlug: func(string) (*resource.BrokerProvider, error) { return githubProvider(), nil },
	}
	resStore := &mockResourceStore{
		resolveFn: func(string) ([]*resource.Resource, error) {
			res := githubBrokerResource()
			res.Policy.Connect.AllowedReturnURLs = []string{"https://other.example.com/back"}
			return []*resource.Resource{res}, nil
		},
	}
	svc, _, _ := newConnectFixture(t, provStore, resStore, &mockBrokerGrantStore{}, &configurableConnectAdapter{}, nil)

	_, err := svc.StartConnect(context.Background(), testUserID, testProvSlug, testResSlug, testReturnURL)
	if !errors.Is(err, domain.ErrInvalidReturnURL) {
		t.Fatalf("StartConnect err = %v, want ErrInvalidReturnURL", err)
	}
}

func TestConnectService_StartConnect_GlobalReturnURLFallback(t *testing.T) {
	provStore := &mockBrokerProviderStore{
		getBySlug: func(string) (*resource.BrokerProvider, error) { return githubProvider(), nil },
	}
	svc, _, _ := newConnectFixture(t, provStore, &mockResourceStore{}, &mockBrokerGrantStore{},
		&configurableConnectAdapter{},
		[]string{testReturnURL},
	)

	if _, err := svc.StartConnect(context.Background(), testUserID, testProvSlug, "", testReturnURL); err != nil {
		t.Fatalf("StartConnect with global allow-list: %v", err)
	}
}

func TestConnectService_StartConnect_ReturnURLToASSelfBypassesPerResourceCheck(t *testing.T) {
	provStore := &mockBrokerProviderStore{
		getBySlug: func(string) (*resource.BrokerProvider, error) { return githubProvider(), nil },
	}
	resStore := &mockResourceStore{
		resolveFn: func(string) ([]*resource.Resource, error) {
			res := githubBrokerResource()
			// Resource policy does NOT include the AS-self URL.
			res.Policy.Connect.AllowedReturnURLs = []string{"https://operator-app.example.com/done"}
			return []*resource.Resource{res}, nil
		},
	}
	svc, _, _ := newConnectFixture(t, provStore, resStore, &mockBrokerGrantStore{}, &configurableConnectAdapter{}, nil)

	if _, err := svc.StartConnect(context.Background(), testUserID, testProvSlug, testResSlug, "https://as.test/connections"); err != nil {
		t.Fatalf("AS-self bypass: %v", err)
	}
}

// TestConnectService_IsReturnURLAllowed_GlobalFallback exercises the
// always-consult-fallback policy on the matcher directly. Pre- the
// global allowedReturnURLs list was silently ignored when target was non-nil,
// which made AUTHPLANE_CONNECT_ALLOWED_RETURN_URLS dead config in any
// deployment with a Broker resource (StartConnect's FK-anchor lookup always
// populates target). The matcher must treat the effective allowlist as
// `target.Policy.Connect.AllowedReturnURLs ∪ global`.
func TestConnectService_IsReturnURLAllowed_GlobalFallback(t *testing.T) {
	const reqURL = "http://localhost:8084/connected"

	withAllowedReturnURLs := func(target []string) *resource.Resource {
		return &resource.Resource{
			Policy: resource.Policy{
				Connect: resource.ConnectPolicy{AllowedReturnURLs: target},
			},
		}
	}

	tests := []struct {
		name        string
		globalList  []string
		targetList  []string // nil = pass nil target; non-nil = pass populated target
		targetIsNil bool
		returnURL   string
		wantAllowed bool
	}{
		{
			name:        " bug repro: global hit, target empty, target non-nil → allowed",
			globalList:  []string{reqURL},
			targetList:  []string{}, // empty list, but target is non-nil
			returnURL:   reqURL,
			wantAllowed: true,
		},
		{
			name:        "global has wrong URL, target empty, target non-nil → rejected",
			globalList:  []string{"http://wrong.example/"},
			targetList:  []string{},
			returnURL:   reqURL,
			wantAllowed: false,
		},
		{
			name:        "back-compat: global empty, target hits → allowed",
			globalList:  nil,
			targetList:  []string{reqURL},
			returnURL:   reqURL,
			wantAllowed: true,
		},
		{
			name:        "both populated, request matches global only → allowed (union)",
			globalList:  []string{reqURL},
			targetList:  []string{"https://other.example/back"},
			returnURL:   reqURL,
			wantAllowed: true,
		},
		{
			name:        "both populated, request matches target only → allowed (union)",
			globalList:  []string{"http://wrong.example/"},
			targetList:  []string{reqURL},
			returnURL:   reqURL,
			wantAllowed: true,
		},
		{
			name:        "both populated, request matches neither → rejected",
			globalList:  []string{"http://a.example/"},
			targetList:  []string{"http://b.example/"},
			returnURL:   reqURL,
			wantAllowed: false,
		},
		{
			name:        "target nil, global hits → allowed (no-resource flow)",
			targetIsNil: true,
			globalList:  []string{reqURL},
			returnURL:   reqURL,
			wantAllowed: true,
		},
		{
			name:        "target nil, global empty → rejected",
			targetIsNil: true,
			globalList:  nil,
			returnURL:   reqURL,
			wantAllowed: false,
		},
		{
			name:        "empty return_url is always rejected",
			globalList:  []string{""},
			targetList:  []string{""},
			returnURL:   "",
			wantAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &ConnectService{
				issuerProvider: static.NewIssuerProvider("https://as.test"),
			}
			var target *resource.Resource
			if !tt.targetIsNil {
				target = withAllowedReturnURLs(tt.targetList)
			}
			got := svc.isReturnURLAllowed(context.Background(), "", tt.returnURL, tt.globalList, target)
			if got != tt.wantAllowed {
				t.Errorf("isReturnURLAllowed(%q, target=%+v) = %v, want %v",
					tt.returnURL, tt.targetList, got, tt.wantAllowed)
			}
		})
	}
}

// TestMatchReturnURL_LoopbackWildcards covers the fix: the connect
// return-URL allowlist must honor loopback-port wildcards
// (`http://localhost:*`, `http://127.0.0.1:*`, and the https variants), which
// is the form shipped in the compose default
// (AUTHPLANE_CONNECT_ALLOWED_RETURN_URLS=http://localhost:*,http://127.0.0.1:*)
// and documented in docs/configuration.md. Pre-fix the matcher compared
// strings literally, so no real browser URL ever matched and every dev-mode
// /connect flow was rejected with `invalid_request: return URL not in
// allowed list`. Glob support is intentionally limited to loopback-with-port;
// broader patterns must NOT match (footgun avoidance + parity with the
// resource_admin.go validateReturnURL gate).
func TestMatchReturnURL_LoopbackWildcards(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		returnURL string
		want      bool
	}{
		// Wildcard hits.
		{
			name:      "localhost wildcard matches port and path",
			pattern:   "http://localhost:*",
			returnURL: "http://localhost:8084/connected",
			want:      true,
		},
		{
			name:      "localhost wildcard matches port without path",
			pattern:   "http://localhost:*",
			returnURL: "http://localhost:8084",
			want:      true,
		},
		{
			name:      "127.0.0.1 wildcard matches port and path",
			pattern:   "http://127.0.0.1:*",
			returnURL: "http://127.0.0.1:8084/connected",
			want:      true,
		},
		{
			name:      "https localhost wildcard matches",
			pattern:   "https://localhost:*",
			returnURL: "https://localhost:9443/cb",
			want:      true,
		},
		{
			name:      "https 127.0.0.1 wildcard matches",
			pattern:   "https://127.0.0.1:*",
			returnURL: "https://127.0.0.1:9443/cb",
			want:      true,
		},

		// Wildcard misses.
		{
			name:      "127.0.0.1 wildcard does not match localhost host",
			pattern:   "http://127.0.0.1:*",
			returnURL: "http://localhost:8084/connected",
			want:      false,
		},
		{
			name:      "localhost wildcard does not match different host",
			pattern:   "http://localhost:*",
			returnURL: "http://example.com/foo",
			want:      false,
		},
		{
			name:      "localhost wildcard requires a port (no port → reject)",
			pattern:   "http://localhost:*",
			returnURL: "http://localhost/no-port",
			want:      false,
		},
		{
			name:      "localhost wildcard rejects empty port (bare host:)",
			pattern:   "http://localhost:*",
			returnURL: "http://localhost:/path",
			want:      false,
		},
		{
			name:      "http wildcard does not match https URL (scheme strict)",
			pattern:   "http://localhost:*",
			returnURL: "https://localhost:8084/connected",
			want:      false,
		},
		{
			name:      "non-numeric port is rejected",
			pattern:   "http://localhost:*",
			returnURL: "http://localhost:abc/x",
			want:      false,
		},
		{
			name:      "broader globs are not honored (no general * support)",
			pattern:   "http://*.example.com/*",
			returnURL: "http://app.example.com/cb",
			want:      false,
		},

		// Exact, non-wildcard entries (back-compat).
		{
			name:      "exact non-wildcard string matches itself",
			pattern:   "https://app.example.com/callback",
			returnURL: "https://app.example.com/callback",
			want:      true,
		},
		{
			name:      "exact non-wildcard string rejects path mismatch",
			pattern:   "https://app.example.com/callback",
			returnURL: "https://app.example.com/other",
			want:      false,
		},
		{
			name:      "exact loopback URL with port still requires byte-equal match",
			pattern:   "http://localhost:8084",
			returnURL: "http://localhost:9999",
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchReturnURL(tc.pattern, tc.returnURL)
			if got != tc.want {
				t.Errorf("matchReturnURL(%q, %q) = %v, want %v",
					tc.pattern, tc.returnURL, got, tc.want)
			}
		})
	}
}

// TestConnectService_IsReturnURLAllowed_LoopbackWildcards drives
// through the full matcher (global + per-target union, plus the AS-self
// bypass path inherited from ). It confirms that wildcard entries are
// honored from EITHER the global list OR the per-resource policy, that
// non-wildcard entries continue to require byte-equal matches, and that an
// empty allowlist still rejects everything.
func TestConnectService_IsReturnURLAllowed_LoopbackWildcards(t *testing.T) {
	const localURL = "http://localhost:8084/connected"

	withTargetList := func(list []string) *resource.Resource {
		return &resource.Resource{
			Policy: resource.Policy{
				Connect: resource.ConnectPolicy{AllowedReturnURLs: list},
			},
		}
	}

	tests := []struct {
		name        string
		globalList  []string
		targetList  []string
		targetIsNil bool
		returnURL   string
		want        bool
	}{
		{
			name:       "wildcard in global list, no target list → allowed",
			globalList: []string{"http://localhost:*"},
			targetList: nil,
			returnURL:  localURL,
			want:       true,
		},
		{
			name:       "wildcard in target list, no global list → allowed (union)",
			globalList: nil,
			targetList: []string{"http://localhost:*"},
			returnURL:  localURL,
			want:       true,
		},
		{
			name:       "compose default (both loopback wildcards) accepts localhost",
			globalList: []string{"http://localhost:*", "http://127.0.0.1:*"},
			targetList: nil,
			returnURL:  localURL,
			want:       true,
		},
		{
			name:       "compose default accepts 127.0.0.1 too",
			globalList: []string{"http://localhost:*", "http://127.0.0.1:*"},
			targetList: nil,
			returnURL:  "http://127.0.0.1:8084/connected",
			want:       true,
		},
		{
			name:       "wildcard does not bridge hosts (127.0.0.1:* alone rejects localhost)",
			globalList: []string{"http://127.0.0.1:*"},
			targetList: nil,
			returnURL:  localURL,
			want:       false,
		},
		{
			name:       "wildcard does not match arbitrary host",
			globalList: []string{"http://localhost:*"},
			targetList: nil,
			returnURL:  "http://example.com/foo",
			want:       false,
		},
		{
			name:       "wildcard requires port (no-port URL rejected)",
			globalList: []string{"http://localhost:*"},
			targetList: nil,
			returnURL:  "http://localhost/no-port",
			want:       false,
		},
		{
			name:       "exact non-wildcard entry still works",
			globalList: []string{"https://app.example.com/cb"},
			targetList: nil,
			returnURL:  "https://app.example.com/cb",
			want:       true,
		},
		{
			name:       "mixed list: exact entry + wildcard, request hits wildcard",
			globalList: []string{"https://app.example.com/cb", "http://localhost:*"},
			targetList: nil,
			returnURL:  localURL,
			want:       true,
		},
		{
			name:       "mixed list: exact entry + wildcard, request hits exact",
			globalList: []string{"https://app.example.com/cb", "http://localhost:*"},
			targetList: nil,
			returnURL:  "https://app.example.com/cb",
			want:       true,
		},
		{
			name:        "empty allowlist still rejects",
			globalList:  nil,
			targetIsNil: true,
			returnURL:   localURL,
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &ConnectService{
				issuerProvider: static.NewIssuerProvider("https://as.test"),
			}
			var target *resource.Resource
			if !tt.targetIsNil {
				target = withTargetList(tt.targetList)
			}
			got := svc.isReturnURLAllowed(context.Background(), "", tt.returnURL, tt.globalList, target)
			if got != tt.want {
				t.Errorf("isReturnURLAllowed(%q) global=%v target=%v = %v, want %v",
					tt.returnURL, tt.globalList, tt.targetList, got, tt.want)
			}
		})
	}
}

// TestConnectService_StartConnect_GlobalReturnURLFallback_WithBrokerAnchor is
// the end-to-end repro:?resource= is omitted, but the FK-anchor
// lookup yields a Broker resource whose Policy.Connect.AllowedReturnURLs is
// empty. Pre-fix the request was rejected because target was non-nil. After
// the fix the global list is consulted and the request goes through.
func TestConnectService_StartConnect_GlobalReturnURLFallback_WithBrokerAnchor(t *testing.T) {
	const globalURL = "http://localhost:8084/connected"

	provStore := &mockBrokerProviderStore{
		getBySlug: func(string) (*resource.BrokerProvider, error) { return githubProvider(), nil },
	}
	// Anchor resource exists (so target != nil), but its policy list is empty.
	resStore := &mockResourceStore{
		listFn: func(filter output.ResourceFilter) ([]*resource.Resource, error) {
			if filter.BackendKind != resource.BackendBroker || filter.BrokerProviderID != testProvID {
				return nil, nil
			}
			anchor := githubBrokerResource()
			anchor.Policy.Connect.AllowedReturnURLs = nil
			return []*resource.Resource{anchor}, nil
		},
	}
	svc, _, _ := newConnectFixture(t, provStore, resStore, &mockBrokerGrantStore{},
		&configurableConnectAdapter{},
		[]string{globalURL}, // global allow-list populated
	)

	if _, err := svc.StartConnect(context.Background(), testUserID, testProvSlug, "", globalURL); err != nil {
		t.Fatalf(": StartConnect with global fallback should succeed; got: %v", err)
	}
}

func TestConnectService_StartConnect_PassesPerProviderCallbackURL(t *testing.T) {
	//  contract: ConnectService computes <redirect_base_url>/connect/<provider>/callback
	// per call and passes it to BuildConnectURL. This is RFC 6749 §4.1.3
	// load-bearing for upstreams that validate redirect_uri (Google, Microsoft).
	provStore := &mockBrokerProviderStore{
		getBySlug: func(string) (*resource.BrokerProvider, error) { return githubProvider(), nil },
	}
	adapter := &configurableConnectAdapter{}
	svc, _, _ := newConnectFixture(t, provStore, &mockResourceStore{}, &mockBrokerGrantStore{}, adapter, []string{testReturnURL})

	if _, err := svc.StartConnect(context.Background(), testUserID, testProvSlug, "", testReturnURL); err != nil {
		t.Fatalf("StartConnect: %v", err)
	}
	wantCallback := "https://as.test/connect/" + testProvSlug + "/callback"
	if got := adapter.lastCallbackURL; got != wantCallback {
		t.Errorf("callbackURL passed to BuildConnectURL = %q, want %q", got, wantCallback)
	}
}

func TestConnectService_CompleteConnect_PassesSameCallbackURLToHandleCallback(t *testing.T) {
	// RFC 6749 §4.1.3: redirect_uri at the token endpoint MUST equal the
	// authorize-endpoint redirect_uri. ConnectService computes the same URL
	// from the provider slug for both calls.
	provider := githubProvider()
	provStore := &mockBrokerProviderStore{
		getByIDFn: func(string) (*resource.BrokerProvider, error) { return provider, nil },
		getBySlug: func(string) (*resource.BrokerProvider, error) { return provider, nil },
	}
	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) { return nil, nil },
	}
	adapter := &configurableConnectAdapter{}
	svc, _, _ := newConnectFixture(t, provStore, &mockResourceStore{}, grants, adapter, []string{testReturnURL})

	upstream, err := svc.StartConnect(context.Background(), testUserID, testProvSlug, "", testReturnURL)
	if err != nil {
		t.Fatalf("StartConnect: %v", err)
	}
	state := extractStateFromURL(t, upstream)
	if _, err := svc.CompleteConnect(context.Background(), testUserID, state, "code"); err != nil {
		t.Fatalf("CompleteConnect: %v", err)
	}

	wantCallback := "https://as.test/connect/" + testProvSlug + "/callback"
	if adapter.lastCallbackURL != wantCallback {
		t.Errorf("BuildConnectURL callback = %q, want %q", adapter.lastCallbackURL, wantCallback)
	}
	if adapter.lastHandleCallbackURL != wantCallback {
		t.Errorf("HandleCallback callback = %q, want %q (RFC 6749 §4.1.3 mismatch)", adapter.lastHandleCallbackURL, wantCallback)
	}
	if adapter.lastCallbackURL != adapter.lastHandleCallbackURL {
		t.Errorf("BuildConnectURL and HandleCallback callbacks must match; got %q vs %q",
			adapter.lastCallbackURL, adapter.lastHandleCallbackURL)
	}
}

func TestConnectService_StartConnect_AdapterErrNoConnectStep(t *testing.T) {
	provStore := &mockBrokerProviderStore{
		getBySlug: func(string) (*resource.BrokerProvider, error) {
			p := githubProvider()
			p.Protocol = "api_key"
			return p, nil
		},
	}
	adapter := &configurableConnectAdapter{name: "api_key", buildErr: output.ErrNoConnectStep}
	svc, _, _ := newConnectFixture(t, provStore, &mockResourceStore{}, &mockBrokerGrantStore{}, adapter, []string{testReturnURL})

	_, err := svc.StartConnect(context.Background(), testUserID, "github", "", testReturnURL)
	if err == nil || !errors.Is(err, domain.ErrInvalidTarget) {
		t.Fatalf("StartConnect err = %v, want ErrInvalidTarget", err)
	}
}

// --- CompleteConnect ---

func TestConnectService_CompleteConnect_HappyPath(t *testing.T) {
	provider := githubProvider()
	provStore := &mockBrokerProviderStore{
		getByIDFn: func(string) (*resource.BrokerProvider, error) { return provider, nil },
		getBySlug: func(string) (*resource.BrokerProvider, error) { return provider, nil },
	}
	resStore := &mockResourceStore{
		resolveFn: func(string) ([]*resource.Resource, error) {
			return []*resource.Resource{githubBrokerResource()}, nil
		},
		getByIDFn: func(string) (*resource.Resource, error) { return githubBrokerResource(), nil },
	}
	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return nil, nil
		},
	}
	adapter := &configurableConnectAdapter{}
	svc, _, rec := newConnectFixture(t, provStore, resStore, grants, adapter, nil)

	upstreamURL, err := svc.StartConnect(context.Background(), testUserID, testProvSlug, testResSlug, testReturnURL)
	if err != nil {
		t.Fatalf("StartConnect: %v", err)
	}
	state := extractStateFromURL(t, upstreamURL)

	result, err := svc.CompleteConnect(context.Background(), testUserID, state, "code-from-upstream")
	if err != nil {
		t.Fatalf("CompleteConnect: %v", err)
	}
	if result.ReturnURL != testReturnURL {
		t.Errorf("ReturnURL = %q, want %q", result.ReturnURL, testReturnURL)
	}
	if result.Meta.Provider != testProvSlug {
		t.Errorf("Meta.Provider = %q", result.Meta.Provider)
	}
	if grants.upsertSeen == nil {
		t.Fatal("grants.Upsert not invoked")
	}
	if grants.upsertSeen.UserID != testUserID || grants.upsertSeen.BrokerProviderID != testProvID {
		t.Errorf("grant key (%q,%q) want (%q,%q)",
			grants.upsertSeen.UserID, grants.upsertSeen.BrokerProviderID, testUserID, testProvID)
	}
	if want := []string{"repo", "read:user"}; !equalStrings(grants.upsertSeen.ScopesGranted, want) {
		t.Errorf("ScopesGranted = %v, want %v", grants.upsertSeen.ScopesGranted, want)
	}

	events := rec.take()
	if len(events) != 1 || events[0].Action != audit.ActionBrokerGrantCreated {
		t.Errorf("audit events = %+v, want one ActionBrokerGrantCreated", events)
	}
}

// TestConnectService_CompleteConnect_ReConnect_Upserts is the
// regression: a second connect for an already-bound (user, provider)
// must succeed via a single Upsert call, NOT lookup → revoke → create
// (which 500'd on the UNIQUE (user_id, broker_provider_id) constraint
// because Revoke is a soft-delete that does not free the slot). The
// audit + log lines must reference the upsert's returned grant id +
// version, not the freshly-generated id we passed in.
func TestConnectService_CompleteConnect_ReConnect_Upserts(t *testing.T) {
	provider := githubProvider()
	provStore := &mockBrokerProviderStore{
		getByIDFn: func(string) (*resource.BrokerProvider, error) { return provider, nil },
		getBySlug: func(string) (*resource.BrokerProvider, error) { return provider, nil },
	}
	resStore := &mockResourceStore{
		resolveFn: func(string) ([]*resource.Resource, error) {
			return []*resource.Resource{githubBrokerResource()}, nil
		},
		getByIDFn: func(string) (*resource.Resource, error) { return githubBrokerResource(), nil },
	}

	// Stand-in for the table: Upsert preserves the existing row's id +
	// bumps version. Get is irrelevant on the Upsert path (no lookup).
	const existingID = "bg-existing"
	grants := &mockBrokerGrantStore{
		upsertFn: func(_ context.Context, g *resource.BrokerGrant) (*resource.BrokerGrant, error) {
			out := *g
			out.ID = existingID // simulate the matched-row id win
			out.Version = 2     // simulate the version bump from 1 → 2
			return &out, nil
		},
	}
	adapter := &configurableConnectAdapter{}
	svc, _, rec := newConnectFixture(t, provStore, resStore, grants, adapter, nil)

	upstreamURL, err := svc.StartConnect(context.Background(), testUserID, testProvSlug, testResSlug, testReturnURL)
	if err != nil {
		t.Fatalf("StartConnect: %v", err)
	}
	state := extractStateFromURL(t, upstreamURL)

	if _, err := svc.CompleteConnect(context.Background(), testUserID, state, "code"); err != nil {
		t.Fatalf("CompleteConnect (re-connect): %v", err)
	}

	if grants.createSeen != nil {
		t.Errorf("grants.Create invoked on re-connect path: %+v (must use Upsert)", grants.createSeen)
	}
	if grants.upsertSeen == nil {
		t.Fatal("grants.Upsert not invoked")
	}
	if grants.revokeSeen != "" {
		t.Errorf("grants.Revoke invoked on re-connect path: %q (Upsert handles resurrect)", grants.revokeSeen)
	}

	// Audit detail must carry the upsert-returned id + version, not
	// the freshly-generated id the service handed in.
	events := rec.take()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1: %+v", len(events), events)
	}
	if events[0].Action != audit.ActionBrokerGrantCreated {
		t.Errorf("audit action = %q, want %q", events[0].Action, audit.ActionBrokerGrantCreated)
	}
	if !strings.Contains(events[0].Detail, "grant_id="+existingID) {
		t.Errorf("audit detail = %q, want grant_id=%s", events[0].Detail, existingID)
	}
	if !strings.Contains(events[0].Detail, "version=2") {
		t.Errorf("audit detail = %q, want version=2", events[0].Detail)
	}
}

func TestConnectService_CompleteConnect_StateConsumedTwice_Fails(t *testing.T) {
	provStore := &mockBrokerProviderStore{
		getBySlug: func(string) (*resource.BrokerProvider, error) { return githubProvider(), nil },
		getByIDFn: func(string) (*resource.BrokerProvider, error) { return githubProvider(), nil },
	}
	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) { return nil, nil },
	}
	svc, _, _ := newConnectFixture(t, provStore, &mockResourceStore{}, grants,
		&configurableConnectAdapter{}, []string{testReturnURL},
	)
	upstream, err := svc.StartConnect(context.Background(), testUserID, testProvSlug, "", testReturnURL)
	if err != nil {
		t.Fatalf("StartConnect: %v", err)
	}
	state := extractStateFromURL(t, upstream)

	if _, err := svc.CompleteConnect(context.Background(), testUserID, state, "code"); err != nil {
		t.Fatalf("first CompleteConnect: %v", err)
	}
	if _, err := svc.CompleteConnect(context.Background(), testUserID, state, "code"); !errors.Is(err, domain.ErrStateNotFound) {
		t.Fatalf("second CompleteConnect err = %v, want ErrStateNotFound", err)
	}
}

func TestConnectService_CompleteConnect_AdapterError_NoGrantPersisted(t *testing.T) {
	provider := githubProvider()
	provStore := &mockBrokerProviderStore{
		getByIDFn: func(string) (*resource.BrokerProvider, error) { return provider, nil },
		getBySlug: func(string) (*resource.BrokerProvider, error) { return provider, nil },
	}
	grants := &mockBrokerGrantStore{}
	adapter := &configurableConnectAdapter{handleErr: errors.New("upstream rejected code")}
	svc, _, _ := newConnectFixture(t, provStore, &mockResourceStore{}, grants, adapter, []string{testReturnURL})

	upstream, err := svc.StartConnect(context.Background(), testUserID, testProvSlug, "", testReturnURL)
	if err != nil {
		t.Fatalf("StartConnect: %v", err)
	}
	state := extractStateFromURL(t, upstream)

	if _, err := svc.CompleteConnect(context.Background(), testUserID, state, "code"); err == nil {
		t.Fatal("CompleteConnect: expected error from adapter, got nil")
	}
	if grants.createSeen != nil {
		t.Errorf("grants.Create invoked despite adapter error: %+v", grants.createSeen)
	}
	if grants.upsertSeen != nil {
		t.Errorf("grants.Upsert invoked despite adapter error: %+v", grants.upsertSeen)
	}
}

// --- Disconnect ---

func TestConnectService_CompleteConnect_TamperedStateHMAC_Rejected(t *testing.T) {
	// Defense-in-depth bypass-path test ( ADV1): if a leaked pending-state
	// ID is replayed with a forged HMAC suffix, the atomic-Consume succeeds but
	// verifyStateToken MUST reject it. Removing the HMAC check at
	// services/connect.go:263 leaves no other defense — this test is the
	// regression guard that ensures it can't be silently retired.
	provider := githubProvider()
	provStore := &mockBrokerProviderStore{
		getByIDFn: func(string) (*resource.BrokerProvider, error) { return provider, nil },
		getBySlug: func(string) (*resource.BrokerProvider, error) { return provider, nil },
	}
	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) { return nil, nil },
	}
	svc, pending, _ := newConnectFixture(t, provStore, &mockResourceStore{}, grants,
		&configurableConnectAdapter{}, []string{testReturnURL},
	)

	upstream, err := svc.StartConnect(context.Background(), testUserID, testProvSlug, "", testReturnURL)
	if err != nil {
		t.Fatalf("StartConnect: %v", err)
	}
	originalState := extractStateFromURL(t, upstream)
	parts := strings.SplitN(originalState, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("state token has unexpected shape: %q", originalState)
	}
	tamperedToken := parts[0] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	// Replay the pending row under the tampered ID so atomic Consume succeeds
	// (the attack model: leaked DB-side ID, forged signature).
	pending.mu.Lock()
	row := pending.rows[originalState]
	pending.rows[tamperedToken] = &resource.ConnectPendingState{
		ID:           tamperedToken,
		UserID:       row.UserID,
		ProviderID:   row.ProviderID,
		ResourceID:   row.ResourceID,
		CodeVerifier: row.CodeVerifier,
		ReturnURL:    row.ReturnURL,
		ExpiresAt:    row.ExpiresAt,
	}
	pending.mu.Unlock()

	_, err = svc.CompleteConnect(context.Background(), testUserID, tamperedToken, "code")
	if !errors.Is(err, domain.ErrInvalidState) {
		t.Fatalf("CompleteConnect with tampered HMAC: got %v, want ErrInvalidState", err)
	}
	if grants.createSeen != nil {
		t.Errorf("grants.Create called despite tampered state: %+v", grants.createSeen)
	}
	if grants.upsertSeen != nil {
		t.Errorf("grants.Upsert called despite tampered state: %+v", grants.upsertSeen)
	}
}

func TestConnectService_CompleteConnect_ForeignUser_Rejected(t *testing.T) {
	// Defense-in-depth bypass-path test ( ADV1 + SEC5 data isolation):
	// user A starts the dance; user B tries to complete it. The pending state's
	// UserID check at services/connect.go:251 must reject the swap so user A's
	// upstream credential cannot be hijacked by user B's session. Removing the
	// check leaves no other defense.
	provider := githubProvider()
	provStore := &mockBrokerProviderStore{
		getByIDFn: func(string) (*resource.BrokerProvider, error) { return provider, nil },
		getBySlug: func(string) (*resource.BrokerProvider, error) { return provider, nil },
	}
	grants := &mockBrokerGrantStore{}
	svc, _, _ := newConnectFixture(t, provStore, &mockResourceStore{}, grants,
		&configurableConnectAdapter{}, []string{testReturnURL},
	)

	upstream, err := svc.StartConnect(context.Background(), "user-A", testProvSlug, "", testReturnURL)
	if err != nil {
		t.Fatalf("StartConnect: %v", err)
	}
	state := extractStateFromURL(t, upstream)

	// user-B tries to complete user-A's pending state.
	_, err = svc.CompleteConnect(context.Background(), "user-B", state, "code")
	if !errors.Is(err, domain.ErrStateForeignUser) {
		t.Fatalf("CompleteConnect with foreign user: got %v, want ErrStateForeignUser", err)
	}
	if grants.createSeen != nil {
		t.Errorf("grants.Create called despite foreign user: %+v", grants.createSeen)
	}
	if grants.upsertSeen != nil {
		t.Errorf("grants.Upsert called despite foreign user: %+v", grants.upsertSeen)
	}
}

func TestConnectService_Disconnect_RevokeBestEffort(t *testing.T) {
	provider := githubProvider()
	provStore := &mockBrokerProviderStore{
		getBySlug: func(string) (*resource.BrokerProvider, error) { return provider, nil },
	}
	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return &resource.BrokerGrant{
				ID:               "grant-1",
				UserID:           testUserID,
				BrokerProviderID: testProvID,
				CredentialData:   []byte("enc:broker:user-1:bp-github-1:" + `{"refresh_token":"rt"}`),
			}, nil
		},
	}
	adapter := &configurableConnectAdapter{revokeErr: errors.New("upstream 500 — best effort")}
	svc, _, rec := newConnectFixture(t, provStore, &mockResourceStore{}, grants, adapter, nil)

	if err := svc.Disconnect(context.Background(), testUserID, testProvSlug); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if grants.revokeSeen != "grant-1" {
		t.Errorf("grants.Revoke seen = %q, want grant-1", grants.revokeSeen)
	}
	if adapter.revokeCalls != 1 {
		t.Errorf("adapter.Revoke calls = %d, want 1", adapter.revokeCalls)
	}
	events := rec.take()
	if len(events) != 1 || events[0].Action != audit.ActionBrokerGrantRevoked {
		t.Errorf("audit events = %+v, want one ActionBrokerGrantRevoked", events)
	}
}

func TestConnectService_Disconnect_NoGrant(t *testing.T) {
	provStore := &mockBrokerProviderStore{
		getBySlug: func(string) (*resource.BrokerProvider, error) { return githubProvider(), nil },
	}
	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) { return nil, nil },
	}
	svc, _, _ := newConnectFixture(t, provStore, &mockResourceStore{}, grants, &configurableConnectAdapter{}, nil)

	if err := svc.Disconnect(context.Background(), testUserID, testProvSlug); !errors.Is(err, domain.ErrConnectionNotFound) {
		t.Fatalf("Disconnect err = %v, want ErrConnectionNotFound", err)
	}
}

// --- ListConnections ---

func TestConnectService_ListConnections_ReturnsActiveOnly(t *testing.T) {
	provider := githubProvider()
	provStore := &mockBrokerProviderStore{
		getByIDFn: func(string) (*resource.BrokerProvider, error) { return provider, nil },
	}
	now := time.Now().UTC()
	revoked := now.Add(-time.Hour)
	grants := &mockBrokerGrantStore{
		listForUser: func(_ string) ([]*resource.BrokerGrant, error) {
			return []*resource.BrokerGrant{
				{ID: "active", UserID: testUserID, BrokerProviderID: testProvID, ScopesGranted: []string{"repo"}, CreatedAt: now, UpdatedAt: now},
				{ID: "revoked", UserID: testUserID, BrokerProviderID: testProvID, ScopesGranted: []string{"old"}, CreatedAt: now, UpdatedAt: now, RevokedAt: &revoked},
			}, nil
		},
	}
	svc, _, _ := newConnectFixture(t, provStore, &mockResourceStore{}, grants, &configurableConnectAdapter{}, nil)

	metas, err := svc.ListConnections(context.Background(), testUserID)
	if err != nil {
		t.Fatalf("ListConnections: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("metas len = %d, want 1; got %+v", len(metas), metas)
	}
	if metas[0].Provider != testProvSlug {
		t.Errorf("Provider = %q", metas[0].Provider)
	}
	if !equalStrings(metas[0].ScopesGranted, []string{"repo"}) {
		t.Errorf("ScopesGranted = %v", metas[0].ScopesGranted)
	}
}

// when /connect/{provider} omits?resource= and the provider has
// ≥2 Broker-backed resources, StartConnect must fail loud rather than
// silently picking rows[0]. The picked resource governs the return-URL
// allowlist and the upstream scope catalog, so a silent guess can issue
// the wrong scopes or allow the wrong return URL.
func TestConnectService_StartConnect_AmbiguousBrokerResource_NoResourceSlug(t *testing.T) {
	provStore := &mockBrokerProviderStore{
		getBySlug: func(string) (*resource.BrokerProvider, error) { return githubProvider(), nil },
	}
	resStore := &mockResourceStore{
		listFn: func(filter output.ResourceFilter) ([]*resource.Resource, error) {
			if filter.BackendKind != resource.BackendBroker || filter.BrokerProviderID != testProvID {
				return nil, nil
			}
			a := githubBrokerResource()
			b := githubBrokerResource()
			b.ID = "res-github-issues-1"
			b.Slug = "github-issues"
			return []*resource.Resource{a, b}, nil
		},
	}
	svc, _, _ := newConnectFixture(t, provStore, resStore, &mockBrokerGrantStore{},
		&configurableConnectAdapter{}, []string{testReturnURL},
	)

	_, err := svc.StartConnect(context.Background(), testUserID, testProvSlug, "", testReturnURL)
	if !errors.Is(err, domain.ErrAmbiguousBrokerResource) {
		t.Fatalf("StartConnect with ambiguous broker resources = %v, want ErrAmbiguousBrokerResource", err)
	}
}

// regression guard: a single Broker resource for the provider must
// keep working when ?resource= is omitted (the unambiguous case). Without
// this, the strict ambiguity check would break the fallback path.
func TestConnectService_StartConnect_SingleBrokerResource_NoResourceSlug(t *testing.T) {
	provStore := &mockBrokerProviderStore{
		getBySlug: func(string) (*resource.BrokerProvider, error) { return githubProvider(), nil },
	}
	// resStore default in newConnectFixture returns a single Broker
	// anchor — exactly the case under test.
	svc, _, _ := newConnectFixture(t, provStore, &mockResourceStore{}, &mockBrokerGrantStore{},
		&configurableConnectAdapter{}, []string{testReturnURL},
	)

	if _, err := svc.StartConnect(context.Background(), testUserID, testProvSlug, "", testReturnURL); err != nil {
		t.Fatalf("StartConnect with single broker resource should still succeed: %v", err)
	}
}

// when?resource= is supplied explicitly, the named resource's
// scope catalog must drive the upstream authorize URL. Pre-fix, a silent
// pick of the wrong anchor would issue scopes from a different resource;
// this test pins the per-resource scope path.
func TestConnectService_StartConnect_ExplicitResourceSlug_UsesResourceScopes(t *testing.T) {
	provStore := &mockBrokerProviderStore{
		getBySlug: func(string) (*resource.BrokerProvider, error) { return githubProvider(), nil },
	}
	resStore := &mockResourceStore{
		resolveFn: func(slug string) ([]*resource.Resource, error) {
			if slug != testResSlug {
				t.Fatalf("resource resolve got %q", slug)
			}
			res := githubBrokerResource()
			res.Scopes = []resource.Scope{
				{Name: "issues:read", Upstream: "issues:read"},
				{Name: "issues:write", Upstream: "issues:write"},
			}
			return []*resource.Resource{res}, nil
		},
	}
	adapter := &configurableConnectAdapter{}
	svc, _, _ := newConnectFixture(t, provStore, resStore, &mockBrokerGrantStore{}, adapter, nil)

	if _, err := svc.StartConnect(context.Background(), testUserID, testProvSlug, testResSlug, testReturnURL); err != nil {
		t.Fatalf("StartConnect: %v", err)
	}
	if !equalStrings(adapter.lastBuildScope, []string{"issues:read", "issues:write"}) {
		t.Errorf("upstream scope = %v, want named resource's scope catalog [issues:read issues:write]", adapter.lastBuildScope)
	}
}

// --- helpers ---

func extractStateFromURL(t *testing.T, urlStr string) string {
	t.Helper()
	idx := strings.Index(urlStr, "state=")
	if idx < 0 {
		t.Fatalf("URL %q has no state param", urlStr)
	}
	rest := urlStr[idx+len("state="):]
	if amp := strings.IndexByte(rest, '&'); amp >= 0 {
		rest = rest[:amp]
	}
	return rest
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
