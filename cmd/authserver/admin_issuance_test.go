package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/admin/dto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
)

func runIssuanceCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return dispatchRoot(t, issuanceCmd, args)
}

func TestIssuanceCmd_List_RequiresAtLeastOneFilter(t *testing.T) {
	stub := &stubIssuanceAdmin{}
	newTestCLIEnv(t, nil, nil, nil, stub)

	_, err := runIssuanceCmd(t, "list")
	if err == nil {
		t.Fatalf("expected error when no filter is set")
	}
	if !strings.Contains(err.Error(), "at least one of") {
		t.Fatalf("expected 'at least one of' error, got %q", err.Error())
	}
}

// relaxed the CLI to accept any combination of --user / --client /
// --resource / --jti. The "mutually exclusive" guard is gone; instead the
// service driver chooses the indexed dimension (user > client > resource)
// and applies a post-filter for the remaining dimensions in-memory.
func TestIssuanceCmd_List_AcceptsCombinedFilters(t *testing.T) {
	rows := []*resource.Issuance{
		{ID: "match", SubjectUserID: "u1", ClientID: "c1", ResourceID: "r1", IssuedAt: time.Now()},
		{ID: "wrong-client", SubjectUserID: "u1", ClientID: "cZ", ResourceID: "r1", IssuedAt: time.Now()},
		{ID: "wrong-resource", SubjectUserID: "u1", ClientID: "c1", ResourceID: "rZ", IssuedAt: time.Now()},
	}
	stub := &stubIssuanceAdmin{
		ListForUserFn: func(_ context.Context, _ string, _ time.Time) ([]*resource.Issuance, error) {
			return rows, nil
		},
	}
	newTestCLIEnv(t, nil, nil, nil, stub)

	out, err := runIssuanceCmd(t, "list",
		"--user", "u1", "--client", "c1", "--resource", "r1", "--json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got dto.IssuanceListResponse
	if jsonErr := json.Unmarshal([]byte(out), &got); jsonErr != nil {
		t.Fatalf("--json output is not valid JSON: %v", jsonErr)
	}
	if got.Count != 1 || got.Issuances[0].ID != "match" {
		t.Fatalf("expected 1 matching row 'match', got %+v", got)
	}
}

func TestIssuanceCmd_List_StandaloneJTI(t *testing.T) {
	row := &resource.Issuance{
		ID:            "iss-1",
		JTI:           "abc123",
		SubjectUserID: "u1",
		ClientID:      "c1",
		ResourceID:    "res-1",
		Scopes:        []string{"repo"},
		BackendKind:   resource.BackendMint,
		Revocable:     true,
		IssuedAt:      time.Now().Add(-time.Hour),
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	var jtiCalledWith string
	stub := &stubIssuanceAdmin{
		GetByJTIFn: func(_ context.Context, jti string) (*resource.Issuance, error) {
			jtiCalledWith = jti
			return row, nil
		},
		ListForUserFn: func(_ context.Context, _ string, _ time.Time) ([]*resource.Issuance, error) {
			t.Fatalf("ListForUser must not be called for the JTI list form")
			return nil, nil
		},
	}
	newTestCLIEnv(t, nil, nil, nil, stub)

	// --jti alone, with no --since: must hit GetByJTI, no time-window filter.
	out, err := runIssuanceCmd(t, "list", "--jti", "abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jtiCalledWith != "abc123" {
		t.Fatalf("expected GetByJTI to receive 'abc123', got %q", jtiCalledWith)
	}
	if !strings.Contains(out, "id=iss-1") {
		t.Fatalf("expected output to include id=iss-1, got %q", out)
	}

	// --jti with --since: --since must be silently ignored, NOT error.
	jtiCalledWith = ""
	if _, err := runIssuanceCmd(t, "list", "--jti", "abc123", "--since", "7d"); err != nil {
		t.Fatalf("unexpected error with --since on jti form: %v", err)
	}
	if jtiCalledWith != "abc123" {
		t.Fatalf("expected --since to be ignored on jti form; GetByJTI called with %q", jtiCalledWith)
	}
}

func TestIssuanceCmd_List_StandaloneJTI_Miss(t *testing.T) {
	stub := &stubIssuanceAdmin{
		GetByJTIFn: func(_ context.Context, _ string) (*resource.Issuance, error) {
			return nil, nil
		},
	}
	newTestCLIEnv(t, nil, nil, nil, stub)

	out, err := runIssuanceCmd(t, "list", "--jti", "missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// On miss the JTI form returns an empty list — list semantics, not 404.
	if !strings.Contains(out, "issuances (0)") {
		t.Fatalf("expected 'issuances (0)' on JTI miss, got %q", out)
	}
}

func TestIssuanceCmd_List_ParsesSinceDuration(t *testing.T) {
	wantWindow := 7 * 24 * time.Hour
	var capturedSince time.Time
	before := time.Now().UTC()
	stub := &stubIssuanceAdmin{
		ListForUserFn: func(_ context.Context, _ string, since time.Time) ([]*resource.Issuance, error) {
			capturedSince = since
			return nil, nil
		},
	}
	newTestCLIEnv(t, nil, nil, nil, stub)

	if _, err := runIssuanceCmd(t, "list", "--user", "u1", "--since", "7d"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	after := time.Now().UTC()

	earliest := before.Add(-wantWindow)
	latest := after.Add(-wantWindow)
	if capturedSince.Before(earliest) || capturedSince.After(latest) {
		t.Fatalf("expected since in [%s, %s], got %s",
			earliest.Format(time.RFC3339Nano),
			latest.Format(time.RFC3339Nano),
			capturedSince.Format(time.RFC3339Nano))
	}
}

func TestIssuanceCmd_List_RejectsSinceOver30Days(t *testing.T) {
	stub := &stubIssuanceAdmin{
		ListForUserFn: func(_ context.Context, _ string, _ time.Time) ([]*resource.Issuance, error) {
			t.Fatalf("ListForUser must not be called when --since exceeds the cap")
			return nil, nil
		},
	}
	newTestCLIEnv(t, nil, nil, nil, stub)

	_, err := runIssuanceCmd(t, "list", "--user", "u1", "--since", "60d")
	if err == nil || !strings.Contains(err.Error(), "30-day cap") {
		t.Fatalf("expected 30-day cap error, got %v", err)
	}
}

func TestIssuanceCmd_GetByID(t *testing.T) {
	row := &resource.Issuance{
		ID:            "iss-42",
		JTI:           "jti-x",
		SubjectUserID: "u1",
		ClientID:      "c1",
		ResourceID:    "res-1",
		Scopes:        []string{"a", "b"},
		BackendKind:   resource.BackendBroker,
		IssuedAt:      time.Unix(1700000000, 0).UTC(),
		ExpiresAt:     time.Unix(1700003600, 0).UTC(),
	}
	stub := &stubIssuanceAdmin{
		GetByIDFn: func(_ context.Context, id string) (*resource.Issuance, error) {
			if id != "iss-42" {
				t.Fatalf("expected GetByID id=iss-42, got %q", id)
			}
			return row, nil
		},
	}
	newTestCLIEnv(t, nil, nil, nil, stub)

	out, err := runIssuanceCmd(t, "get", "--id", "iss-42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "id=iss-42") || !strings.Contains(out, "jti=jti-x") {
		t.Fatalf("expected id+jti in output, got %q", out)
	}

	// --json variant
	out, err = runIssuanceCmd(t, "get", "--id", "iss-42", "--json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got dto.IssuanceView
	if jsonErr := json.Unmarshal([]byte(out), &got); jsonErr != nil {
		t.Fatalf("--json output is not valid JSON: %v\noutput=%s", jsonErr, out)
	}
	if got.ID != "iss-42" || got.JTI != "jti-x" {
		t.Fatalf("unexpected --json shape: %+v", got)
	}
}

func TestIssuanceCmd_GetByID_NotFound_Returns1(t *testing.T) {
	stub := &stubIssuanceAdmin{
		GetByIDFn: func(_ context.Context, _ string) (*resource.Issuance, error) {
			return nil, domain.ErrIssuanceNotFound
		},
	}
	newTestCLIEnv(t, nil, nil, nil, stub)

	if _, err := runIssuanceCmd(t, "get", "--id", "missing"); err == nil {
		t.Fatalf("expected error for ErrIssuanceNotFound")
	}
}

func TestIssuanceCmd_Revoke(t *testing.T) {
	var revokedID string
	stub := &stubIssuanceAdmin{
		RevokeFn: func(_ context.Context, id string) error {
			revokedID = id
			return nil
		},
	}
	newTestCLIEnv(t, nil, nil, nil, stub)

	out, err := runIssuanceCmd(t, "revoke", "--id", "iss-99")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if revokedID != "iss-99" {
		t.Fatalf("expected Revoke to receive 'iss-99', got %q", revokedID)
	}
	if !strings.Contains(out, "issuance revoked: id=iss-99") {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestIssuanceCmd_Revoke_PropagatesError(t *testing.T) {
	stub := &stubIssuanceAdmin{
		RevokeFn: func(_ context.Context, _ string) error {
			return errors.New("storage failure")
		},
	}
	newTestCLIEnv(t, nil, nil, nil, stub)

	if _, err := runIssuanceCmd(t, "revoke", "--id", "x"); err == nil {
		t.Fatalf("expected error to propagate from service")
	}
}

func TestIssuanceCmd_List_LimitTruncates(t *testing.T) {
	rows := []*resource.Issuance{
		{ID: "1", IssuedAt: time.Now()},
		{ID: "2", IssuedAt: time.Now()},
		{ID: "3", IssuedAt: time.Now()},
	}
	stub := &stubIssuanceAdmin{
		ListForUserFn: func(_ context.Context, _ string, _ time.Time) ([]*resource.Issuance, error) {
			return rows, nil
		},
	}
	newTestCLIEnv(t, nil, nil, nil, stub)

	out, err := runIssuanceCmd(t, "list", "--user", "u1", "--limit", "2", "--json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got dto.IssuanceListResponse
	if jsonErr := json.Unmarshal([]byte(out), &got); jsonErr != nil {
		t.Fatalf("--json output is not valid JSON: %v", jsonErr)
	}
	if got.Count != 2 || len(got.Issuances) != 2 {
		t.Fatalf("expected 2 rows after --limit, got %d", got.Count)
	}
}
