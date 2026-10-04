package services

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/input"
)

// Fronted token exchange, every combination of (scope_map shape x subject
// scope set x requested scope) against an independent oracle.
//
// The oracle below is written from the fronting specification, not from the
// production helpers (frontedMintTargetsFor, frontedBrokerTargetsFor,
// requiredSourceScopesForTargets, validateBrokerTargets): it must not call
// them, and it must not be "fixed" by copying their logic. When the oracle
// and the service disagree, one of them is wrong about the specification,
// and the disagreement is the finding.
//
// The specification the oracle encodes. A fronting link maps source-resource
// scopes to target-resource scopes, scope_map[src] = [tgt...]. A subject token
// (aud = source) carries a set S of source scopes. The request carries no
// scope (omitted) or a set R of target scopes.
//
// Mint target. reverse(t) is the sorted list of source keys whose value list
// contains t; the source required for t is reverse(t)[0].
//   - R omitted: D = { t : reverse(t)[0] in S }. D empty -> invalid_scope.
//     Otherwise issued with scope = D (sorted, space-separated).
//   - R given: a t with no reverse -> invalid_scope (unmapped). Otherwise a t
//     with reverse(t)[0] not in S -> invalid_scope (subject insufficient).
//     Otherwise issued with scope = R.
//
// Broker target.
//   - R omitted: D = union of scope_map[s] for s in S. D empty -> refused
//     subject_scope_insufficient, nothing vended. Otherwise vended for D.
//   - R given: a t that is no value in the map -> refused scope_unmapped.
//     Otherwise a t no source key in S maps to -> refused
//     subject_scope_insufficient. Otherwise vended for R.
//
// Refusals never produce a token. Issued Mint tokens carry aud = target URI,
// client_id = source slug and act.sub = source slug.
//
// Every earlier fronted test sent a scope parameter, which is how an omitted
// scope came to skip the scope_map entirely. The matrix therefore treats
// "omitted" as a first-class request shape for every map and every subject.

// fmMatrixMap is one scope_map shape under test.
type fmMatrixMap struct {
	name string
	m    map[string][]string
}

// fmMatrixMaps are the scope_map shapes the matrix enumerates. Source keys are
// lower-case (a, b, c); target names come from the target catalog AA..DD.
var fmMatrixMaps = []fmMatrixMap{
	{"1to1", map[string][]string{"a": {"AA"}}},
	{"1toN", map[string][]string{"a": {"AA", "BB"}}},
	{"Nto1", map[string][]string{"a": {"AA"}, "b": {"AA"}}},
	{"overlap", map[string][]string{"a": {"AA"}, "b": {"AA", "BB"}}},
	{"disjoint", map[string][]string{"a": {"AA"}, "b": {"BB"}, "c": {"CC"}}},
}

const (
	// fmExtraSourceKey is a source scope the subject may hold that no map
	// entry names. It must never open anything.
	fmExtraSourceKey = "x"
	// fmNotInCatalog is a target scope absent from every map and from the
	// target resource's catalog.
	fmNotInCatalog = "ZZ"
)

// fmTargetCatalog is the target resource's scope catalog. DD is never a map
// value, so it is always "in the catalog but not in the map".
var fmTargetCatalog = []string{"AA", "BB", "CC", "DD"}

// fmSourceCatalog is the source resource's scope catalog.
var fmSourceCatalog = []string{"a", "b", "c", fmExtraSourceKey}

// ---------------------------------------------------------------------------
// Oracle — plain rules from the specification above.
// ---------------------------------------------------------------------------

type fmOutcome struct {
	issued bool
	// scopes is the sorted scope set the issued token (Mint) or the vend
	// (Broker) must carry. Nil on refusal.
	scopes []string
	// reason is the refusal reason: for Mint the dispatch denial reason
	// (fronting_scope_unmapped / fronting_subject_scope_insufficient), for
	// Broker the ConsentRequiredError.DeniedReason (scope_unmapped /
	// subject_scope_insufficient). Empty when issued.
	reason string
}

func fmHas(set []string, s string) bool {
	for _, v := range set {
		if v == s {
			return true
		}
	}
	return false
}

// fmSourcesFor returns the sorted source keys whose value list contains t.
func fmSourcesFor(m map[string][]string, t string) []string {
	var out []string
	for src, tgts := range m {
		if fmHas(tgts, t) {
			out = append(out, src)
		}
	}
	sort.Strings(out)
	return out
}

// fmAllTargets returns every target named anywhere in the map, sorted.
func fmAllTargets(m map[string][]string) []string {
	var out []string
	for _, tgts := range m {
		for _, t := range tgts {
			if !fmHas(out, t) {
				out = append(out, t)
			}
		}
	}
	sort.Strings(out)
	return out
}

func fmSorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func oracleMint(m map[string][]string, subject []string, requested []string, omitted bool) fmOutcome {
	if omitted {
		var derived []string
		for _, t := range fmAllTargets(m) {
			if fmHas(subject, fmSourcesFor(m, t)[0]) {
				derived = append(derived, t)
			}
		}
		if len(derived) == 0 {
			return fmOutcome{reason: "fronting_subject_scope_insufficient"}
		}
		return fmOutcome{issued: true, scopes: fmSorted(derived)}
	}
	for _, t := range requested {
		if len(fmSourcesFor(m, t)) == 0 {
			return fmOutcome{reason: "fronting_scope_unmapped"}
		}
	}
	for _, t := range requested {
		if !fmHas(subject, fmSourcesFor(m, t)[0]) {
			return fmOutcome{reason: "fronting_subject_scope_insufficient"}
		}
	}
	return fmOutcome{issued: true, scopes: fmSorted(requested)}
}

func oracleBroker(m map[string][]string, subject []string, requested []string, omitted bool) fmOutcome {
	if omitted {
		var derived []string
		for _, s := range subject {
			for _, t := range m[s] {
				if !fmHas(derived, t) {
					derived = append(derived, t)
				}
			}
		}
		if len(derived) == 0 {
			return fmOutcome{reason: "subject_scope_insufficient"}
		}
		return fmOutcome{issued: true, scopes: fmSorted(derived)}
	}
	for _, t := range requested {
		if len(fmSourcesFor(m, t)) == 0 {
			return fmOutcome{reason: "scope_unmapped"}
		}
	}
	for _, t := range requested {
		covered := false
		for _, src := range fmSourcesFor(m, t) {
			if fmHas(subject, src) {
				covered = true
			}
		}
		if !covered {
			return fmOutcome{reason: "subject_scope_insufficient"}
		}
	}
	return fmOutcome{issued: true, scopes: fmSorted(requested)}
}

// ---------------------------------------------------------------------------
// Enumeration.
// ---------------------------------------------------------------------------

// fmSubjectSets returns every subset of the map's source keys plus the
// unmapped extra key, including the empty set. Each subset is sorted.
func fmSubjectSets(m map[string][]string) [][]string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	keys = append(keys, fmExtraSourceKey)
	sort.Strings(keys)
	var out [][]string
	for mask := 0; mask < 1<<len(keys); mask++ {
		var s []string
		for i, k := range keys {
			if mask&(1<<i) != 0 {
				s = append(s, k)
			}
		}
		out = append(out, s)
	}
	return out
}

type fmRequest struct {
	omitted bool
	scopes  []string // sorted
}

func (r fmRequest) label() string {
	if r.omitted {
		return "omitted"
	}
	return strings.Join(r.scopes, "+")
}

func (r fmRequest) scopeParam() string {
	if r.omitted {
		return ""
	}
	return strings.Join(r.scopes, " ")
}

// fmRequests returns the request shapes for a map: omitted; every single map
// target; every pair; all map targets; every catalog target outside the map;
// one target outside the catalog; and one mapped target mixed with one
// outside the map. Duplicates are dropped.
func fmRequests(m map[string][]string) []fmRequest {
	targets := fmAllTargets(m)
	out := []fmRequest{{omitted: true}}
	seen := map[string]bool{}
	add := func(s ...string) {
		s = fmSorted(s)
		key := strings.Join(s, " ")
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, fmRequest{scopes: s})
	}
	for _, t := range targets {
		add(t)
	}
	for i := 0; i < len(targets); i++ {
		for j := i + 1; j < len(targets); j++ {
			add(targets[i], targets[j])
		}
	}
	add(targets...)
	for _, c := range fmTargetCatalog {
		if !fmHas(targets, c) {
			add(c)
		}
	}
	add(fmNotInCatalog)
	add(targets[0], "DD")
	return out
}

func fmSubjectLabel(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, "+")
}

// fmNewEvents returns the audit events recorded since the recorder held
// `before` events.
func fmNewEvents(rec *captureAuditRecorder, before int) []audit.Event {
	all := rec.take()
	return all[before:]
}

// ---------------------------------------------------------------------------
// Oracle self-check. The oracle is small, but it is the thing every other
// assertion rests on; pin a handful of hand-computed rows so a slip in it
// cannot silently agree with a slip in production.
// ---------------------------------------------------------------------------

func TestFrontingMatrix_OracleSelfCheck(t *testing.T) {
	overlap := map[string][]string{"a": {"AA"}, "b": {"AA", "BB"}}
	nto1 := map[string][]string{"a": {"AA"}, "b": {"AA"}}
	cases := []struct {
		name string
		got  fmOutcome
		want fmOutcome
	}{
		{"mint overlap {b} omitted -> BB only (AA needs a)", oracleMint(overlap, []string{"b"}, nil, true), fmOutcome{issued: true, scopes: []string{"BB"}}},
		{"mint overlap {a} omitted -> AA", oracleMint(overlap, []string{"a"}, nil, true), fmOutcome{issued: true, scopes: []string{"AA"}}},
		{"mint Nto1 {b} omitted -> refused", oracleMint(nto1, []string{"b"}, nil, true), fmOutcome{reason: "fronting_subject_scope_insufficient"}},
		{"mint Nto1 {b} AA -> refused", oracleMint(nto1, []string{"b"}, []string{"AA"}, false), fmOutcome{reason: "fronting_subject_scope_insufficient"}},
		{"mint {} omitted -> refused", oracleMint(overlap, nil, nil, true), fmOutcome{reason: "fronting_subject_scope_insufficient"}},
		{"mint {a b} AA+DD -> unmapped wins", oracleMint(overlap, []string{"a", "b"}, []string{"AA", "DD"}, false), fmOutcome{reason: "fronting_scope_unmapped"}},
		{"broker Nto1 {b} omitted -> AA", oracleBroker(nto1, []string{"b"}, nil, true), fmOutcome{issued: true, scopes: []string{"AA"}}},
		{"broker overlap {b} AA -> vended", oracleBroker(overlap, []string{"b"}, []string{"AA"}, false), fmOutcome{issued: true, scopes: []string{"AA"}}},
		{"broker {x} omitted -> refused", oracleBroker(overlap, []string{"x"}, nil, true), fmOutcome{reason: "subject_scope_insufficient"}},
		{"broker {} ZZ -> unmapped", oracleBroker(overlap, nil, []string{"ZZ"}, false), fmOutcome{reason: "scope_unmapped"}},
	}
	for _, c := range cases {
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("%s: oracle = %+v, want %+v", c.name, c.got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Mint matrix.
// ---------------------------------------------------------------------------

// fmMintFixture is stdFixture with catalogs sized for the matrix: source
// [a b c x], target [AA BB CC DD].
func fmMintFixture(t *testing.T, sm map[string][]string) *frontingFixture {
	t.Helper()
	f := newFrontingFixture(t)
	f.source = f.seedResource(frSourceSlug, frSourceURI, fmSourceCatalog)
	f.bindGateway(frAgentID)
	f.target = f.seedResource(frTargetSlug, frTargetURI, fmTargetCatalog)
	f.seedFrontingLink(frSourceSlug, frTargetSlug, resource.ScopeMap(sm))
	return f
}

func TestFrontingMatrix_Mint(t *testing.T) {
	total, issued := 0, 0
	for _, mp := range fmMatrixMaps {
		f := fmMintFixture(t, mp.m)
		for _, subject := range fmSubjectSets(mp.m) {
			for _, req := range fmRequests(mp.m) {
				total++
				want := oracleMint(mp.m, subject, req.scopes, req.omitted)
				if want.issued {
					issued++
				}
				name := "map=" + mp.name + "/subject=" + fmSubjectLabel(subject) + "/scope=" + req.label()
				t.Run(name, func(t *testing.T) {
					f.t = t
					before := len(f.auditRec.take())
					subj := subjectClaimsForFronting(strings.Join(subject, " "), frAgentID, []string{frSourceURI})
					resp, parsed, err := f.dispatchMintFronted(input.TokenExchangeRequest{
						ClientID: frAgentID,
						Resource: frTargetSlug,
						Scope:    req.scopeParam(),
					}, subj, f.target)
					events := fmNewEvents(f.auditRec, before)

					if !want.issued {
						if err == nil || resp != nil {
							t.Fatalf("want refusal (%s), got a token (scope %q) err=%v", want.reason, fmScopeOf(parsed), err)
						}
						if !errors.Is(err, domain.ErrInvalidScope) {
							t.Errorf("refusal does not wrap ErrInvalidScope: %v", err)
						}
						var cre *domain.ConsentRequiredError
						if errors.As(err, &cre) {
							t.Errorf("fronted Mint refusal surfaced ConsentRequiredError: %+v", cre)
						}
						fmAssertMintDenialAudit(t, events, want.reason)
						return
					}

					if err != nil {
						t.Fatalf("want issued scope %q, got err=%v", strings.Join(want.scopes, " "), err)
					}
					wantScope := strings.Join(want.scopes, " ")
					if parsed.Scope != wantScope {
						t.Errorf("token scope = %q, want %q", parsed.Scope, wantScope)
					}
					if resp.Scope != wantScope {
						t.Errorf("response scope = %q, want %q", resp.Scope, wantScope)
					}
					if !reflect.DeepEqual(parsed.Audience, []string{frTargetURI}) {
						t.Errorf("aud = %v, want [%s]", parsed.Audience, frTargetURI)
					}
					if parsed.ClientID != frSourceSlug {
						t.Errorf("client_id = %q, want %q", parsed.ClientID, frSourceSlug)
					}
					if got, _ := parsed.Act["sub"].(string); got != frSourceSlug {
						t.Errorf("act.sub = %v, want %q", parsed.Act["sub"], frSourceSlug)
					}
					fmAssertMintSuccessAudit(t, events, wantScope)
				})
			}
		}
	}
	t.Logf("fronted Mint matrix: %d combinations (%d issued, %d refused)", total, issued, total-issued)
}

func fmScopeOf(c *crypto.AccessTokenClaims) string {
	if c == nil {
		return "<no token>"
	}
	return c.Scope
}

func fmAssertMintDenialAudit(t *testing.T, events []audit.Event, reason string) {
	t.Helper()
	var denied []audit.Event
	for _, ev := range events {
		switch ev.Action {
		case audit.ActionTokenExchanged:
			t.Errorf("refusal recorded a token.exchanged event: %s", ev.Detail)
		case audit.ActionTokenExchangeDenied:
			denied = append(denied, ev)
		}
	}
	if len(denied) != 1 {
		t.Fatalf("refusal recorded %d token.exchange_denied events, want 1: %+v", len(denied), denied)
	}
	if want := "reason=" + reason; denied[0].Detail != want {
		t.Errorf("denial detail = %q, want %q", denied[0].Detail, want)
	}
}

func fmAssertMintSuccessAudit(t *testing.T, events []audit.Event, wantScope string) {
	t.Helper()
	var exchanged []audit.Event
	for _, ev := range events {
		switch ev.Action {
		case audit.ActionTokenExchangeDenied:
			t.Errorf("issued exchange recorded a denial: %s", ev.Detail)
		case audit.ActionTokenExchanged:
			exchanged = append(exchanged, ev)
		}
	}
	if len(exchanged) != 1 {
		t.Fatalf("issued exchange recorded %d token.exchanged events, want 1", len(exchanged))
	}
	if got := fmDetailField(exchanged[0].Detail, "scopes", "chain_kind"); got != wantScope {
		t.Errorf("audit scopes = %q, want %q (detail %q)", got, wantScope, exchanged[0].Detail)
	}
	if !strings.Contains(exchanged[0].Detail, "chain_kind=fronted") {
		t.Errorf("audit detail missing chain_kind=fronted: %q", exchanged[0].Detail)
	}
}

// fmDetailField extracts the value of key= from an audit detail string. The
// value may contain spaces (a scope list), so it runs up to " <next>=".
func fmDetailField(detail, key, next string) string {
	start := strings.Index(detail, key+"=")
	if start < 0 {
		return "<absent>"
	}
	rest := detail[start+len(key)+1:]
	if end := strings.Index(rest, " "+next+"="); end >= 0 {
		return rest[:end]
	}
	return rest
}

// ---------------------------------------------------------------------------
// Broker matrix.
// ---------------------------------------------------------------------------

const fmVendToken = "upstream-matrix-token"

// fmBrokerFixture is stdBrokerFixture with the broker target's catalog
// replaced by AA..DD (upstream up:AA..up:DD) and an active upstream grant
// covering all of them, so the only gate that can refuse is the fronting
// link's.
func fmBrokerFixture(t *testing.T, sm map[string][]string) *brokerFixture {
	t.Helper()
	f := stdBrokerFixture(t)
	var upstream []string
	f.brokerTarget.Scopes = nil
	for _, c := range fmTargetCatalog {
		f.brokerTarget.Scopes = append(f.brokerTarget.Scopes, resource.Scope{Name: c, Upstream: "up:" + c})
		upstream = append(upstream, "up:"+c)
	}
	if err := f.resources.Update(context.Background(), f.brokerTarget); err != nil {
		t.Fatalf("update broker target catalog: %v", err)
	}
	f.seedActiveGrant(frUserID, upstream)
	f.adapter.vendAccessToken = fmVendToken
	f.seedFrontingLink(frSourceSlug, frBrokerTargetSlug, resource.ScopeMap(sm))
	return f
}

func TestFrontingMatrix_Broker(t *testing.T) {
	total, issued := 0, 0
	for _, mp := range fmMatrixMaps {
		f := fmBrokerFixture(t, mp.m)
		for _, subject := range fmSubjectSets(mp.m) {
			for _, req := range fmRequests(mp.m) {
				total++
				want := oracleBroker(mp.m, subject, req.scopes, req.omitted)
				if want.issued {
					issued++
				}
				name := "map=" + mp.name + "/subject=" + fmSubjectLabel(subject) + "/scope=" + req.label()
				t.Run(name, func(t *testing.T) {
					f.t = t
					before := len(f.auditRec.take())
					vendBefore := f.adapter.vendCalls
					subj := subjectClaimsForFronting(strings.Join(subject, " "), frAgentID, []string{frSourceURI})
					resp, err := f.dispatchBrokerFronted(input.TokenExchangeRequest{
						ClientID: frAgentID,
						Resource: frBrokerTargetSlug,
						Scope:    req.scopeParam(),
					}, subj)
					events := fmNewEvents(f.auditRec, before)
					vendDelta := f.adapter.vendCalls - vendBefore

					if !want.issued {
						if err == nil || resp != nil {
							t.Fatalf("want refusal (%s), got resp=%+v err=%v", want.reason, resp, err)
						}
						var cre *domain.ConsentRequiredError
						if !errors.As(err, &cre) {
							t.Fatalf("refusal is not a ConsentRequiredError: %v", err)
						}
						if cre.DeniedReason != want.reason {
							t.Errorf("DeniedReason = %q, want %q", cre.DeniedReason, want.reason)
						}
						if cre.Cause != domain.CauseScopeInsufficient {
							t.Errorf("Cause = %q, want %q", cre.Cause, domain.CauseScopeInsufficient)
						}
						if vendDelta != 0 {
							t.Errorf("vendCalls delta = %d, want 0: a refused exchange vended the upstream credential", vendDelta)
						}
						fmAssertBrokerDenialAudit(t, events, want.reason)
						return
					}

					if err != nil {
						t.Fatalf("want vend for %q, got err=%v", strings.Join(want.scopes, " "), err)
					}
					if resp == nil || resp.AccessToken != fmVendToken {
						t.Fatalf("resp = %+v, want the vended upstream token", resp)
					}
					if vendDelta != 1 {
						t.Errorf("vendCalls delta = %d, want 1", vendDelta)
					}
					if got := fmSorted(f.adapter.lastScopes); !reflect.DeepEqual(got, want.scopes) {
						t.Errorf("vended scopes = %v, want %v", got, want.scopes)
					}
					fmAssertBrokerSuccessAudit(t, events, strings.Join(want.scopes, " "))
				})
			}
		}
	}
	t.Logf("fronted Broker matrix: %d combinations (%d issued, %d refused)", total, issued, total-issued)
}

func fmAssertBrokerDenialAudit(t *testing.T, events []audit.Event, reason string) {
	t.Helper()
	var denied []audit.Event
	for _, ev := range events {
		switch ev.Action {
		case audit.ActionTokenExchanged:
			t.Errorf("refusal recorded a token.exchanged event: %s", ev.Detail)
		case audit.ActionTokenExchangeDenied:
			denied = append(denied, ev)
		}
	}
	if len(denied) != 1 {
		t.Fatalf("refusal recorded %d token.exchange_denied events, want 1", len(denied))
	}
	if !strings.HasSuffix(denied[0].Detail, " denied_reason="+reason) {
		t.Errorf("denial detail = %q, want denied_reason=%s", denied[0].Detail, reason)
	}
}

func fmAssertBrokerSuccessAudit(t *testing.T, events []audit.Event, wantScope string) {
	t.Helper()
	var dispatch []audit.Event
	for _, ev := range events {
		if ev.Action == audit.ActionTokenExchangeDenied {
			t.Errorf("vended exchange recorded a denial: %s", ev.Detail)
		}
		if ev.Action == audit.ActionTokenExchanged && strings.Contains(ev.Detail, "type=broker_dispatch") {
			dispatch = append(dispatch, ev)
		}
	}
	if len(dispatch) != 1 {
		t.Fatalf("vended exchange recorded %d broker_dispatch token.exchanged events, want 1", len(dispatch))
	}
	if got := fmDetailField(dispatch[0].Detail, "scopes", "chain_kind"); got != wantScope {
		t.Errorf("audit scopes = %q, want %q (detail %q)", got, wantScope, dispatch[0].Detail)
	}
}
