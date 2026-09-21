package testdata

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/output"
)

// IssuanceStoreSuiteDeps bundles the stores and helpers an
// IssuanceStore integration suite needs. The suite seeds its own users
// and Mint resources; ExplainQueryPlan is a backend-specific shim that
// returns the planner output as a single string the suite greps for
// index names.
type IssuanceStoreSuiteDeps struct {
	Issuances output.IssuanceStore
	Resources output.ResourceStore
	Users     output.UserStore

	// ExplainQueryPlan returns the EXPLAIN output for the given query
	// joined into one lower-cased string. SQLite uses
	// "EXPLAIN QUERY PLAN", postgres uses "EXPLAIN" — each backend
	// supplies the right adapter so the suite can grep for
	// "idx_issuances_..." substrings portably.
	ExplainQueryPlan func(t *testing.T, query string, args ...any) string
}

// RunIssuanceStoreTests runs the integration test suite against the
// supplied factory.
func RunIssuanceStoreTests(t *testing.T, newDeps func(*testing.T) IssuanceStoreSuiteDeps) {
	t.Helper()

	t.Run("Insert_RoundtripsAgentChain", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-rt-chain")
		r := seedMintResource(t, deps.Resources, "r-rt-chain", "rt-chain")

		now := time.Now().UTC().Truncate(time.Second)
		chain := []string{"agent-root", "agent-mid", "agent-leaf"}
		i := newMintIssuance("iss-rt-chain", "u-rt-chain", "c-rt-chain", r.ID, now)
		i.AgentID = "agent-root"
		i.AgentChain = chain
		if err := deps.Issuances.Insert(ctx, i); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := deps.Issuances.GetByJTI(ctx, i.JTI)
		if err != nil {
			t.Fatalf("get by jti: %v", err)
		}
		if got == nil {
			t.Fatal("expected issuance, got nil")
		}
		if got.AgentID != "agent-root" {
			t.Errorf("agent_id = %q, want agent-root", got.AgentID)
		}
		if !reflect.DeepEqual(got.AgentChain, chain) {
			t.Errorf("agent_chain round-trip: got %v, want %v", got.AgentChain, chain)
		}
	})

	t.Run("Insert_RoundtripsDPoPJKT", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-rt-jkt")
		r := seedMintResource(t, deps.Resources, "r-rt-jkt", "rt-jkt")

		now := time.Now().UTC().Truncate(time.Second)
		i := newMintIssuance("iss-rt-jkt", "u-rt-jkt", "c-rt-jkt", r.ID, now)
		i.DPoPJKT = "ZUVwG-dpop-jkt-base64url"
		if err := deps.Issuances.Insert(ctx, i); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := deps.Issuances.GetByJTI(ctx, i.JTI)
		if err != nil {
			t.Fatalf("get by jti: %v", err)
		}
		if got == nil {
			t.Fatal("expected issuance, got nil")
		}
		if got.DPoPJKT != i.DPoPJKT {
			t.Errorf("dpop_jkt round-trip: got %q, want %q", got.DPoPJKT, i.DPoPJKT)
		}
	})

	t.Run("GetByJTI_NotFound", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		got, err := deps.Issuances.GetByJTI(ctx, "no-such-jti")
		if err != nil {
			t.Fatalf("get by jti: %v", err)
		}
		if got != nil {
			t.Fatalf("expected nil for missing jti, got %+v", got)
		}
	})

	// GetByID is the by-id lookup added in  for the admin
	// path-keyed GET /admin/issuances/{id}. It must hit Mint AND Broker
	// rows (Broker issuances have empty jti per  — GetByJTI can't
	// find them, but GetByID can) and round-trip on a miss as
	// (nil, nil) parallel to GetByJTI.
	t.Run("GetByID_RoundTripsMintAndBroker", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-gbi")
		r := seedMintResource(t, deps.Resources, "r-gbi", "gbi")

		now := time.Now().UTC().Truncate(time.Second)
		mintRow := newMintIssuance("iss-gbi-mint", "u-gbi", "c-gbi", r.ID, now)
		brokerRow := newBrokerIssuance("iss-gbi-broker", "u-gbi", "c-gbi", r.ID, now)
		if err := deps.Issuances.Insert(ctx, mintRow); err != nil {
			t.Fatalf("insert mint: %v", err)
		}
		if err := deps.Issuances.Insert(ctx, brokerRow); err != nil {
			t.Fatalf("insert broker: %v", err)
		}

		gotMint, err := deps.Issuances.GetByID(ctx, "iss-gbi-mint")
		if err != nil {
			t.Fatalf("GetByID mint: %v", err)
		}
		if gotMint == nil || gotMint.ID != "iss-gbi-mint" {
			t.Fatalf("GetByID mint: got %+v", gotMint)
		}
		if gotMint.JTI == "" {
			t.Error("mint issuance: expected non-empty jti round-trip")
		}

		gotBroker, err := deps.Issuances.GetByID(ctx, "iss-gbi-broker")
		if err != nil {
			t.Fatalf("GetByID broker: %v", err)
		}
		if gotBroker == nil || gotBroker.ID != "iss-gbi-broker" {
			t.Fatalf("GetByID broker: got %+v", gotBroker)
		}
		// The whole point of GetByID is that broker rows (with empty
		// jti) remain reachable.
		if gotBroker.JTI != "" {
			t.Errorf("broker issuance: jti = %q, want \"\" ( contract)", gotBroker.JTI)
		}
	})

	t.Run("GetByID_NotFound_ReturnsNilNoError", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		got, err := deps.Issuances.GetByID(ctx, "no-such-id")
		if err != nil {
			t.Fatalf("GetByID miss returned error: %v (expected nil)", err)
		}
		if got != nil {
			t.Errorf("GetByID miss: got %+v, want nil", got)
		}
	})

	t.Run("GetByJTI_PartialIndex", func(t *testing.T) {
		deps := newDeps(t)
		if deps.ExplainQueryPlan == nil {
			t.Skip("backend does not provide an EXPLAIN helper")
		}
		plan := strings.ToLower(deps.ExplainQueryPlan(t,
			`SELECT id FROM issuances WHERE jti = $1`, "any-jti",
		))
		if !strings.Contains(plan, "idx_issuances_jti") {
			t.Errorf("EXPLAIN did not use idx_issuances_jti partial index:\n%s", plan)
		}
	})

	t.Run("Revoke_SetsRevokedAt", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-rev")
		r := seedMintResource(t, deps.Resources, "r-rev", "rev-ts")

		now := time.Now().UTC().Truncate(time.Second)
		i := newMintIssuance("iss-rev", "u-rev", "c-rev", r.ID, now)
		if err := deps.Issuances.Insert(ctx, i); err != nil {
			t.Fatalf("insert: %v", err)
		}

		before := time.Now().UTC()
		if err := deps.Issuances.Revoke(ctx, "iss-rev"); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		after := time.Now().UTC()

		got, err := deps.Issuances.GetByJTI(ctx, i.JTI)
		if err != nil {
			t.Fatalf("get by jti: %v", err)
		}
		if got == nil || got.RevokedAt == nil {
			t.Fatalf("expected revoked timestamp, got %+v", got)
		}
		ts := *got.RevokedAt
		if ts.Before(before.Add(-time.Second)) || ts.After(after.Add(time.Second)) {
			t.Errorf("revoked_at = %v, expected within [%v, %v]", ts, before, after)
		}
	})

	t.Run("RevokeFamily_FiltersBrokerKind", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-fam")
		r := seedMintResource(t, deps.Resources, "r-fam", "rev-fam")

		now := time.Now().UTC().Truncate(time.Second)
		mintRow := newMintIssuance("iss-fam-mint", "u-fam", "c-fam", r.ID, now)
		brokerRow := newBrokerIssuance("iss-fam-broker", "u-fam", "c-fam", r.ID, now)
		if err := deps.Issuances.Insert(ctx, mintRow); err != nil {
			t.Fatalf("insert mint: %v", err)
		}
		if err := deps.Issuances.Insert(ctx, brokerRow); err != nil {
			t.Fatalf("insert broker: %v", err)
		}

		n, err := deps.Issuances.RevokeFamily(ctx, "u-fam", "c-fam", r.ID)
		if err != nil {
			t.Fatalf("revoke family: %v", err)
		}
		if n != 1 {
			t.Fatalf("rows revoked = %d, want 1 (mint only)", n)
		}

		// Mint row revoked.
		mintGot, err := deps.Issuances.GetByJTI(ctx, mintRow.JTI)
		if err != nil {
			t.Fatalf("get mint: %v", err)
		}
		if mintGot == nil || mintGot.RevokedAt == nil {
			t.Errorf("mint issuance not marked revoked: %+v", mintGot)
		}

		// Broker row still active. List for the actor and check.
		all, err := deps.Issuances.ListForActor(ctx, "c-fam", time.Time{})
		if err != nil {
			t.Fatalf("list for actor: %v", err)
		}
		var brokerRevoked *time.Time
		for _, x := range all {
			if x.ID == "iss-fam-broker" {
				brokerRevoked = x.RevokedAt
			}
		}
		if brokerRevoked != nil {
			t.Errorf("broker issuance unexpectedly revoked: %v", *brokerRevoked)
		}
	})

	// The consent-revocation cascade. The grant is (user, app A,
	// resource R). Rows are written the way token exchange writes them:
	// client_id is the acting client, consent_client_id is A, parent_jti is
	// the token the row was exchanged from.
	t.Run("RevokeFamily_MatchesConsentClientNotActor", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-lin")
		r := seedMintResource(t, deps.Resources, "r-lin", "lin")

		now := time.Now().UTC().Truncate(time.Second)
		// Service X exchanged app A's user token for R. The acting client
		// is X; the consent that authorized it belongs to A.
		hop1 := newMintIssuance("iss-lin-hop1", "u-lin", "client-X", r.ID, now)
		hop1.ConsentClientID = "client-A"
		hop1.ParentJTI = "jti-user-token-no-row"
		if err := deps.Issuances.Insert(ctx, hop1); err != nil {
			t.Fatalf("insert hop1: %v", err)
		}
		// A sibling grant (user, app B, R) minted its own token through the
		// same service. Revoking A's consent must not touch it.
		sibling := newMintIssuance("iss-lin-sibling", "u-lin", "client-X", r.ID, now)
		sibling.ConsentClientID = "client-B"
		if err := deps.Issuances.Insert(ctx, sibling); err != nil {
			t.Fatalf("insert sibling: %v", err)
		}

		n, err := deps.Issuances.RevokeFamily(ctx, "u-lin", "client-A", r.ID)
		if err != nil {
			t.Fatalf("revoke family: %v", err)
		}
		if n != 1 {
			t.Fatalf("rows revoked = %d, want 1", n)
		}
		assertRevoked(t, deps.Issuances, hop1.JTI, true)
		assertRevoked(t, deps.Issuances, sibling.JTI, false)
	})

	t.Run("RevokeFamily_FollowsParentJTIAcrossResources", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-chain")
		r1 := seedMintResource(t, deps.Resources, "r-chain-1", "chain-1")
		r2 := seedMintResource(t, deps.Resources, "r-chain-2", "chain-2")
		r3 := seedMintResource(t, deps.Resources, "r-chain-3", "chain-3")

		now := time.Now().UTC().Truncate(time.Second)
		// A's user token → X exchanges for R1 (under A's consent)
		//               → Y exchanges X's token for R2 (under X's consent)
		//               → Z exchanges Y's token for R3 (under Y's consent)
		hop1 := newMintIssuance("iss-ch-1", "u-chain", "client-X", r1.ID, now)
		hop1.ConsentClientID = "client-A"
		hop1.ParentJTI = "jti-root"
		hop2 := newMintIssuance("iss-ch-2", "u-chain", "client-Y", r2.ID, now.Add(time.Second))
		hop2.ConsentClientID = "client-X"
		hop2.ParentJTI = hop1.JTI
		hop3 := newMintIssuance("iss-ch-3", "u-chain", "client-Z", r3.ID, now.Add(2*time.Second))
		hop3.ConsentClientID = "client-Y"
		hop3.ParentJTI = hop2.JTI
		// An unrelated token for R2 under the same consent X holds, derived
		// from a different root. Revoking A's grant must leave it alone:
		// X's consent for R2 is not what was revoked.
		other := newMintIssuance("iss-ch-other", "u-chain", "client-Y", r2.ID, now)
		other.ConsentClientID = "client-X"
		other.ParentJTI = "jti-some-other-root"
		for _, row := range []*resource.Issuance{hop1, hop2, hop3, other} {
			if err := deps.Issuances.Insert(ctx, row); err != nil {
				t.Fatalf("insert %s: %v", row.ID, err)
			}
		}

		n, err := deps.Issuances.RevokeFamily(ctx, "u-chain", "client-A", r1.ID)
		if err != nil {
			t.Fatalf("revoke family: %v", err)
		}
		if n != 3 {
			t.Fatalf("rows revoked = %d, want 3 (the whole chain)", n)
		}
		assertRevoked(t, deps.Issuances, hop1.JTI, true)
		assertRevoked(t, deps.Issuances, hop2.JTI, true)
		assertRevoked(t, deps.Issuances, hop3.JTI, true)
		assertRevoked(t, deps.Issuances, other.JTI, false)

		// Idempotent: a second revoke of the same grant changes nothing.
		n, err = deps.Issuances.RevokeFamily(ctx, "u-chain", "client-A", r1.ID)
		if err != nil {
			t.Fatalf("second revoke: %v", err)
		}
		if n != 0 {
			t.Errorf("second revoke rows = %d, want 0", n)
		}
	})

	// A root the operator already revoked one at a time is still a root
	// for the walk: its descendants must not survive because of it.
	t.Run("RevokeFamily_ReachesDescendantsOfAlreadyRevokedRoot", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-pre")
		r1 := seedMintResource(t, deps.Resources, "r-pre-1", "pre-1")
		r2 := seedMintResource(t, deps.Resources, "r-pre-2", "pre-2")

		now := time.Now().UTC().Truncate(time.Second)
		hop1 := newMintIssuance("iss-pre-1", "u-pre", "client-X", r1.ID, now)
		hop1.ConsentClientID = "client-A"
		hop2 := newMintIssuance("iss-pre-2", "u-pre", "client-Y", r2.ID, now)
		hop2.ConsentClientID = "client-X"
		hop2.ParentJTI = hop1.JTI
		for _, row := range []*resource.Issuance{hop1, hop2} {
			if err := deps.Issuances.Insert(ctx, row); err != nil {
				t.Fatalf("insert %s: %v", row.ID, err)
			}
		}
		if err := deps.Issuances.Revoke(ctx, hop1.ID); err != nil {
			t.Fatalf("pre-revoke hop1: %v", err)
		}

		n, err := deps.Issuances.RevokeFamily(ctx, "u-pre", "client-A", r1.ID)
		if err != nil {
			t.Fatalf("revoke family: %v", err)
		}
		if n != 1 {
			t.Fatalf("rows revoked = %d, want 1 (hop2; hop1 was already revoked)", n)
		}
		assertRevoked(t, deps.Issuances, hop2.JTI, true)
	})

	// Rows written before the lineage columns existed carry no
	// consent_client_id. For those the cascade matches the acting client,
	// which is what it matched before, so an upgrade does not lose the
	// self-exchange case that used to work.
	t.Run("RevokeFamily_LegacyRowsMatchActingClient", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-legacy")
		r := seedMintResource(t, deps.Resources, "r-legacy", "legacy")

		now := time.Now().UTC().Truncate(time.Second)
		legacy := newMintIssuance("iss-legacy", "u-legacy", "client-A", r.ID, now)
		// No ConsentClientID, no ParentJTI: a pre-013 row.
		crossClient := newMintIssuance("iss-legacy-x", "u-legacy", "client-X", r.ID, now)
		// Also legacy, but a cross-client mint: unreachable before, and
		// still unreachable — there is nothing on the row to match.
		for _, row := range []*resource.Issuance{legacy, crossClient} {
			if err := deps.Issuances.Insert(ctx, row); err != nil {
				t.Fatalf("insert %s: %v", row.ID, err)
			}
		}

		n, err := deps.Issuances.RevokeFamily(ctx, "u-legacy", "client-A", r.ID)
		if err != nil {
			t.Fatalf("revoke family: %v", err)
		}
		if n != 1 {
			t.Fatalf("rows revoked = %d, want 1", n)
		}
		assertRevoked(t, deps.Issuances, legacy.JTI, true)
		assertRevoked(t, deps.Issuances, crossClient.JTI, false)
	})

	// Another user's tokens under the same client and resource are not the
	// grant's, and a parent link never crosses users because a derived token
	// carries its subject's sub — but the roots must still filter on it.
	t.Run("RevokeFamily_DoesNotCrossUsers", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-one")
		seedUser(t, deps.Users, "u-two")
		r := seedMintResource(t, deps.Resources, "r-users", "users")

		now := time.Now().UTC().Truncate(time.Second)
		mine := newMintIssuance("iss-u-one", "u-one", "client-X", r.ID, now)
		mine.ConsentClientID = "client-A"
		theirs := newMintIssuance("iss-u-two", "u-two", "client-X", r.ID, now)
		theirs.ConsentClientID = "client-A"
		for _, row := range []*resource.Issuance{mine, theirs} {
			if err := deps.Issuances.Insert(ctx, row); err != nil {
				t.Fatalf("insert %s: %v", row.ID, err)
			}
		}
		n, err := deps.Issuances.RevokeFamily(ctx, "u-one", "client-A", r.ID)
		if err != nil {
			t.Fatalf("revoke family: %v", err)
		}
		if n != 1 {
			t.Fatalf("rows revoked = %d, want 1", n)
		}
		assertRevoked(t, deps.Issuances, mine.JTI, true)
		assertRevoked(t, deps.Issuances, theirs.JTI, false)
	})

	// A parent cycle cannot be written by the service (a parent is always
	// issued before its child), but a corrupted table must not hang the
	// cascade. UNION in the recursive CTE terminates it; every row in the
	// cycle is revoked.
	t.Run("RevokeFamily_TerminatesOnCorruptCycle", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-cyc")
		r := seedMintResource(t, deps.Resources, "r-cyc", "cyc")

		now := time.Now().UTC().Truncate(time.Second)
		a := newMintIssuance("iss-cyc-a", "u-cyc", "client-X", r.ID, now)
		a.ConsentClientID = "client-A"
		a.ParentJTI = "jti-iss-cyc-c" // points forward to c
		b := newMintIssuance("iss-cyc-b", "u-cyc", "client-Y", r.ID, now)
		b.ParentJTI = a.JTI
		c := newMintIssuance("iss-cyc-c", "u-cyc", "client-Z", r.ID, now)
		c.ParentJTI = b.JTI // closes the cycle a -> b -> c -> a
		for _, row := range []*resource.Issuance{a, b, c} {
			if err := deps.Issuances.Insert(ctx, row); err != nil {
				t.Fatalf("insert %s: %v", row.ID, err)
			}
		}
		done := make(chan struct{})
		var n int
		var err error
		go func() {
			n, err = deps.Issuances.RevokeFamily(ctx, "u-cyc", "client-A", r.ID)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("RevokeFamily did not terminate on a cyclic parent chain")
		}
		if err != nil {
			t.Fatalf("revoke family: %v", err)
		}
		if n != 3 {
			t.Fatalf("rows revoked = %d, want 3", n)
		}
	})

	// The deepest chain the server can mint (token_exchange.max_chain_depth
	// caps at 10) is reached end to end.
	t.Run("RevokeFamily_ReachesDepthTen", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-deep")
		r := seedMintResource(t, deps.Resources, "r-deep", "deep")

		now := time.Now().UTC().Truncate(time.Second)
		parent := ""
		var jtis []string
		for i := 0; i < 10; i++ {
			row := newMintIssuance("iss-deep-"+string(rune('a'+i)), "u-deep", "client-"+string(rune('a'+i)), r.ID, now.Add(time.Duration(i)*time.Second))
			if i == 0 {
				row.ConsentClientID = "client-A"
			}
			row.ParentJTI = parent
			if err := deps.Issuances.Insert(ctx, row); err != nil {
				t.Fatalf("insert %s: %v", row.ID, err)
			}
			parent = row.JTI
			jtis = append(jtis, row.JTI)
		}
		n, err := deps.Issuances.RevokeFamily(ctx, "u-deep", "client-A", r.ID)
		if err != nil {
			t.Fatalf("revoke family: %v", err)
		}
		if n != 10 {
			t.Fatalf("rows revoked = %d, want 10", n)
		}
		for _, j := range jtis {
			assertRevoked(t, deps.Issuances, j, true)
		}
	})

	// A descendant on another resource is reached even though the root
	// filter names one resource: the walk follows parent_jti, not
	// resource_id. Pinned separately from the chain test so a "helpful"
	// resource filter on the recursive arm cannot slip in.
	t.Run("RevokeFamily_DescendantOnOtherResourceReached", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-xres")
		r1 := seedMintResource(t, deps.Resources, "r-xres-1", "xres-1")
		r2 := seedMintResource(t, deps.Resources, "r-xres-2", "xres-2")

		now := time.Now().UTC().Truncate(time.Second)
		root := newMintIssuance("iss-xres-root", "u-xres", "client-A", r1.ID, now)
		root.ConsentClientID = "client-A"
		leaf := newMintIssuance("iss-xres-leaf", "u-xres", "client-Y", r2.ID, now)
		leaf.ConsentClientID = "client-A"
		leaf.ParentJTI = root.JTI
		for _, row := range []*resource.Issuance{root, leaf} {
			if err := deps.Issuances.Insert(ctx, row); err != nil {
				t.Fatalf("insert %s: %v", row.ID, err)
			}
		}
		if n, err := deps.Issuances.RevokeFamily(ctx, "u-xres", "client-A", r1.ID); err != nil || n != 2 {
			t.Fatalf("revoke family: n=%d err=%v, want 2", n, err)
		}
		assertRevoked(t, deps.Issuances, leaf.JTI, true)
	})

	t.Run("Insert_RoundtripsLineage", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-rt")
		r := seedMintResource(t, deps.Resources, "r-rt", "rt")

		row := newMintIssuance("iss-rt", "u-rt", "client-X", r.ID, time.Now().UTC().Truncate(time.Second))
		row.ConsentClientID = "client-A"
		row.ParentJTI = "jti-parent"
		if err := deps.Issuances.Insert(ctx, row); err != nil {
			t.Fatalf("insert: %v", err)
		}
		got, err := deps.Issuances.GetByJTI(ctx, row.JTI)
		if err != nil || got == nil {
			t.Fatalf("get: %v %v", got, err)
		}
		if got.ConsentClientID != "client-A" || got.ParentJTI != "jti-parent" {
			t.Errorf("lineage did not round-trip: consent=%q parent=%q", got.ConsentClientID, got.ParentJTI)
		}
	})

	t.Run("ListForActor_UsesIndex", func(t *testing.T) {
		deps := newDeps(t)
		if deps.ExplainQueryPlan == nil {
			t.Skip("backend does not provide an EXPLAIN helper")
		}
		plan := strings.ToLower(deps.ExplainQueryPlan(t,
			`SELECT id FROM issuances WHERE client_id = $1 AND issued_at >= $2 ORDER BY issued_at DESC`,
			"c-explain", time.Now().UTC().Add(-time.Hour),
		))
		if !strings.Contains(plan, "idx_issuances_client_issued") {
			t.Errorf("EXPLAIN did not use idx_issuances_client_issued:\n%s", plan)
		}
	})

	t.Run("ListForUser_OrdersByIssuedAtDesc", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-order")
		r := seedMintResource(t, deps.Resources, "r-order", "order")

		base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
		// Insert in middle, oldest, newest order to prove the store sorts,
		// not insertion order.
		for j, off := range []time.Duration{30 * time.Minute, 0, time.Hour} {
			i := newMintIssuance(idAt("iss-order", j), "u-order", "c-order", r.ID, base.Add(off))
			if err := deps.Issuances.Insert(ctx, i); err != nil {
				t.Fatalf("insert %d: %v", j, err)
			}
		}

		got, err := deps.Issuances.ListForUser(ctx, "u-order", time.Time{})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("len = %d, want 3", len(got))
		}
		for k := 1; k < len(got); k++ {
			if got[k-1].IssuedAt.Before(got[k].IssuedAt) {
				t.Errorf("ListForUser not desc-ordered: %v then %v",
					got[k-1].IssuedAt, got[k].IssuedAt)
			}
		}
	})

	t.Run("PurgeExpired_RespectsRevokedWindow", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-purge")
		r := seedMintResource(t, deps.Resources, "r-purge", "purge")

		now := time.Now().UTC().Truncate(time.Second)
		// Row 1: not revoked, expired 10 days ago — should drop.
		oldExpired := newMintIssuance("iss-purge-old-exp", "u-purge", "c-purge", r.ID, now.Add(-30*24*time.Hour))
		oldExpired.ExpiresAt = now.Add(-10 * 24 * time.Hour)

		// Row 2: revoked 10 days ago — should drop.
		oldRevoked := newMintIssuance("iss-purge-old-rev", "u-purge", "c-purge", r.ID, now.Add(-30*24*time.Hour))
		oldRevoked.ExpiresAt = now.Add(20 * 24 * time.Hour) // not expired by clock
		ts := now.Add(-10 * 24 * time.Hour)
		oldRevoked.RevokedAt = &ts

		// Row 3: recent — should survive.
		recent := newMintIssuance("iss-purge-recent", "u-purge", "c-purge", r.ID, now)
		recent.ExpiresAt = now.Add(time.Hour)

		// Row 4: expired but within window — should survive.
		recentExpired := newMintIssuance("iss-purge-recent-exp", "u-purge", "c-purge", r.ID, now.Add(-time.Hour))
		recentExpired.ExpiresAt = now.Add(-30 * time.Minute)

		for _, x := range []*resource.Issuance{oldExpired, oldRevoked, recent, recentExpired} {
			if err := deps.Issuances.Insert(ctx, x); err != nil {
				t.Fatalf("insert %s: %v", x.ID, err)
			}
		}

		cutoff := now.Add(-7 * 24 * time.Hour)
		n, err := deps.Issuances.PurgeExpired(ctx, cutoff)
		if err != nil {
			t.Fatalf("purge: %v", err)
		}
		if n != 2 {
			t.Errorf("purged = %d, want 2 (oldExpired + oldRevoked)", n)
		}

		// Survivors are still queryable.
		left, err := deps.Issuances.ListForUser(ctx, "u-purge", time.Time{})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		survived := map[string]bool{}
		for _, x := range left {
			survived[x.ID] = true
		}
		if !survived["iss-purge-recent"] || !survived["iss-purge-recent-exp"] {
			t.Errorf("expected recent survivors, got %v", survived)
		}
		if survived["iss-purge-old-exp"] || survived["iss-purge-old-rev"] {
			t.Errorf("expected old rows purged, got survivors %v", survived)
		}
	})

	t.Run("FK_ResourceMustExist", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-fk")

		now := time.Now().UTC().Truncate(time.Second)
		i := newMintIssuance("iss-fk", "u-fk", "c-fk", "r-does-not-exist", now)
		err := deps.Issuances.Insert(ctx, i)
		if err == nil {
			t.Fatal("expected FK violation on missing resource_id, got nil")
		}
		if !looksLikeFKError(err) {
			t.Fatalf("expected FK error, got: %v", err)
		}
	})
}

// newMintIssuance builds a Mint-kind issuance with revocable=true and a
// non-empty jti so GetByJTI / Revoke / RevokeFamily reach the row.
func newMintIssuance(id, userID, clientID, resourceID string, issuedAt time.Time) *resource.Issuance {
	return &resource.Issuance{
		ID:            id,
		SubjectUserID: userID,
		ClientID:      clientID,
		ResourceID:    resourceID,
		Scopes:        []string{"calendar:read"},
		BackendKind:   resource.BackendMint,
		Revocable:     true,
		IssuedAt:      issuedAt,
		ExpiresAt:     issuedAt.Add(time.Hour),
		JTI:           "jti-" + id,
	}
}

// newBrokerIssuance builds a Broker-kind issuance with revocable=false
// and an empty jti — Broker tokens cannot be revoked or introspected by
// the AS.
func newBrokerIssuance(id, userID, clientID, resourceID string, issuedAt time.Time) *resource.Issuance {
	return &resource.Issuance{
		ID:            id,
		SubjectUserID: userID,
		ClientID:      clientID,
		ResourceID:    resourceID,
		Scopes:        []string{"calendar:read"},
		BackendKind:   resource.BackendBroker,
		Revocable:     false,
		IssuedAt:      issuedAt,
		ExpiresAt:     issuedAt.Add(time.Hour),
	}
}

// idAt is a small helper to derive deterministic per-iteration IDs.
func idAt(prefix string, n int) string {
	switch n {
	case 0:
		return prefix + "-a"
	case 1:
		return prefix + "-b"
	case 2:
		return prefix + "-c"
	default:
		return prefix + "-x"
	}
}

// assertRevoked fails the test unless the issuance with the given jti has
// the expected revocation state.
func assertRevoked(t *testing.T, store output.IssuanceStore, jti string, want bool) {
	t.Helper()
	got, err := store.GetByJTI(context.Background(), jti)
	if err != nil {
		t.Fatalf("get %s: %v", jti, err)
	}
	if got == nil {
		t.Fatalf("get %s: no row", jti)
	}
	if (got.RevokedAt != nil) != want {
		t.Errorf("%s revoked = %v, want %v", jti, got.RevokedAt != nil, want)
	}
}
