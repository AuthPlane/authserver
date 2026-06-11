package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"testing"
)

func TestParseOnly(t *testing.T) {
	allNames := []string{
		"jti", "refresh-tokens", "dpop-nonces",
		"machine-tokens", "assertion-jti", "sessions", "connect-pending-states",
	}

	tests := []struct {
		name      string
		input     string
		wantCount int    // expected number of selected targets; -1 means nil map (all)
		wantErr   string // substring expected in error; empty means no error
	}{
		{
			name:      "empty selects all",
			input:     "",
			wantCount: -1,
		},
		{
			name:      "single valid target",
			input:     "jti",
			wantCount: 1,
		},
		{
			name:      "multiple valid targets",
			input:     "jti,refresh-tokens,sessions",
			wantCount: 3,
		},
		{
			name:      "all 7 targets",
			input:     strings.Join(allNames, ","),
			wantCount: 7,
		},
		{
			name:      "whitespace trimmed",
			input:     " jti , sessions ",
			wantCount: 2,
		},
		{
			name:    "unknown target",
			input:   "bogus",
			wantErr: `unknown purge target "bogus"`,
		},
		{
			name:    "mix valid and invalid",
			input:   "jti,bogus",
			wantErr: `unknown purge target "bogus"`,
		},
		{
			name:    "only commas",
			input:   ",,,",
			wantErr: "--only requires at least one target",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOnly(tt.input)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantCount == -1 {
				if got != nil {
					t.Fatalf("expected nil map (all), got %v", got)
				}
				return
			}

			if len(got) != tt.wantCount {
				t.Fatalf("expected %d selected targets, got %d: %v", tt.wantCount, len(got), got)
			}
		})
	}
}

func TestPurgeOpFactoriesAreSorted(t *testing.T) {
	names := purgeTargetNames()
	if !sort.StringsAreSorted(names) {
		t.Fatalf("purgeOpFactories must be sorted by name; got %v", names)
	}
}

func TestPurgeOpFactoriesMatchExpected(t *testing.T) {
	expected := []string{
		"assertion-jti",
		"connect-pending-states",
		"dpop-nonces",
		"jti",
		"machine-tokens",
		"refresh-tokens",
		"sessions",
	}
	got := purgeTargetNames()
	if len(got) != len(expected) {
		t.Fatalf("expected %d purge targets, got %d: %v", len(expected), len(got), got)
	}
	for i, name := range expected {
		if got[i] != name {
			t.Fatalf("purgeTargetNames()[%d] = %q, want %q", i, got[i], name)
		}
	}
}

func TestValidPurgeNamesListIsDeterministic(t *testing.T) {
	first := validPurgeNamesList()
	for range 10 {
		if got := validPurgeNamesList(); got != first {
			t.Fatalf("validPurgeNamesList() is non-deterministic: %q vs %q", first, got)
		}
	}
}

func TestRunPurge(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	t.Run("all ops succeed with counts", func(t *testing.T) {
		ops := []purgeOp{
			{name: "a", runFn: func(_ context.Context) (int64, error) { return 5, nil }},
			{name: "b", runFn: func(_ context.Context) (int64, error) { return 0, nil }},
		}
		if err := runPurge(context.Background(), logger, ops, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("all ops succeed without counts", func(t *testing.T) {
		ops := []purgeOp{
			{name: "a", runFn: func(_ context.Context) (int64, error) { return -1, nil }},
			{name: "b", runFn: func(_ context.Context) (int64, error) { return -1, nil }},
		}
		if err := runPurge(context.Background(), logger, ops, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("one op fails others continue", func(t *testing.T) {
		called := map[string]bool{}
		ops := []purgeOp{
			{name: "a", runFn: func(_ context.Context) (int64, error) { called["a"] = true; return 5, nil }},
			{name: "b", runFn: func(_ context.Context) (int64, error) { called["b"] = true; return 0, fmt.Errorf("boom") }},
			{name: "c", runFn: func(_ context.Context) (int64, error) { called["c"] = true; return 3, nil }},
		}
		err := runPurge(context.Background(), logger, ops, nil)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "one or more purge operations failed") {
			t.Fatalf("unexpected error message: %v", err)
		}
		for _, name := range []string{"a", "b", "c"} {
			if !called[name] {
				t.Errorf("op %q was not called", name)
			}
		}
	})

	t.Run("selected filter limits ops", func(t *testing.T) {
		called := map[string]bool{}
		ops := []purgeOp{
			{name: "a", runFn: func(_ context.Context) (int64, error) { called["a"] = true; return 1, nil }},
			{name: "b", runFn: func(_ context.Context) (int64, error) { called["b"] = true; return 2, nil }},
			{name: "c", runFn: func(_ context.Context) (int64, error) { called["c"] = true; return 3, nil }},
		}
		selected := map[string]bool{"a": true, "c": true}
		if err := runPurge(context.Background(), logger, ops, selected); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !called["a"] {
			t.Error("op 'a' should have been called")
		}
		if called["b"] {
			t.Error("op 'b' should NOT have been called")
		}
		if !called["c"] {
			t.Error("op 'c' should have been called")
		}
	})

	t.Run("op returning context error aborts remaining ops", func(t *testing.T) {
		called := map[string]bool{}
		ops := []purgeOp{
			{name: "a", runFn: func(_ context.Context) (int64, error) { called["a"] = true; return 1, nil }},
			{name: "b", runFn: func(_ context.Context) (int64, error) {
				called["b"] = true
				return 0, context.DeadlineExceeded
			}},
			{name: "c", runFn: func(_ context.Context) (int64, error) { called["c"] = true; return 3, nil }},
		}
		err := runPurge(context.Background(), logger, ops, nil)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !called["a"] || !called["b"] {
			t.Errorf("ops a and b should have been called: %v", called)
		}
		if called["c"] {
			t.Error("op c should NOT have been called after context deadline")
		}
	})

	t.Run("already-canceled context aborts before first op", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // cancel immediately

		called := map[string]bool{}
		ops := []purgeOp{
			{name: "a", runFn: func(_ context.Context) (int64, error) { called["a"] = true; return 1, nil }},
		}
		err := runPurge(ctx, logger, ops, nil)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if called["a"] {
			t.Error("op a should NOT have been called with a pre-canceled context")
		}
	})
}
