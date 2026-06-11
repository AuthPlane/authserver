//go:build integration

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/testdata"
)

func TestPurgeIntegration_AllTables(t *testing.T) {
	ctx := context.Background()
	ds := testdata.SetupTestDB(t)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	now := time.Now().UTC()
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)

	// token_families.client_id / user_id are FK-enforced.
	testdata.SeedClientAndUser(t, ds.Client(), ds.User(), "client-1", "user-1")

	// --- Seed a token family ---
	fam := &token.Family{
		ID:        "fam-purge",
		ClientID:  "client-1",
		UserID:    "user-1",
		Scope:     "tools/query",
		Resource:  "https://mcp.example.com",
		Status:    token.FamilyActive,
		CreatedAt: now,
	}
	if err := ds.Token().CreateFamily(ctx, fam); err != nil {
		t.Fatalf("create family: %v", err)
	}

	// Expired refresh token
	rtExpired := &token.RefreshToken{
		ID:        "rt-expired",
		FamilyID:  "fam-purge",
		TokenHash: "hash-expired",
		ExpiresAt: past,
		CreatedAt: now,
	}
	if err := ds.Token().CreateRefreshToken(ctx, rtExpired); err != nil {
		t.Fatalf("create expired refresh token: %v", err)
	}

	// Active refresh token
	rtActive := &token.RefreshToken{
		ID:        "rt-active",
		FamilyID:  "fam-purge",
		TokenHash: "hash-active",
		ExpiresAt: future,
		CreatedAt: now,
	}
	if err := ds.Token().CreateRefreshToken(ctx, rtActive); err != nil {
		t.Fatalf("create active refresh token: %v", err)
	}

	// --- Run full purge (selected = nil → all tables) ---
	ops := buildPurgeOps(ds)
	if err := runPurge(ctx, logger, ops, nil); err != nil {
		t.Fatalf("runPurge: %v", err)
	}

	// Expired refresh token should be gone
	_, err := ds.Token().GetRefreshTokenByHash(ctx, "hash-expired")
	if err == nil {
		t.Error("expected error looking up expired refresh token, got nil")
	} else if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("expected ErrInvalidGrant for expired RT, got: %v", err)
	}

	// Active refresh token should still exist
	got, err := ds.Token().GetRefreshTokenByHash(ctx, "hash-active")
	if err != nil {
		t.Errorf("active refresh token should exist, got error: %v", err)
	}
	if got != nil && got.ID != "rt-active" {
		t.Errorf("expected rt-active, got %s", got.ID)
	}
}

func TestPurgeIntegration_OnlyFilter(t *testing.T) {
	ctx := context.Background()
	ds := testdata.SetupTestDB(t)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	now := time.Now().UTC()
	past := now.Add(-24 * time.Hour)

	// token_families.client_id / user_id are FK-enforced.
	testdata.SeedClientAndUser(t, ds.Client(), ds.User(), "client-1", "user-1")

	// --- Seed a token family ---
	fam := &token.Family{
		ID:        "fam-filter",
		ClientID:  "client-1",
		UserID:    "user-1",
		Scope:     "tools/query",
		Resource:  "https://mcp.example.com",
		Status:    token.FamilyActive,
		CreatedAt: now,
	}
	if err := ds.Token().CreateFamily(ctx, fam); err != nil {
		t.Fatalf("create family: %v", err)
	}

	// Expired refresh token
	rtExpired := &token.RefreshToken{
		ID:        "rt-expired-filter",
		FamilyID:  "fam-filter",
		TokenHash: "hash-expired-filter",
		ExpiresAt: past,
		CreatedAt: now,
	}
	if err := ds.Token().CreateRefreshToken(ctx, rtExpired); err != nil {
		t.Fatalf("create expired refresh token: %v", err)
	}

	// --- Run purge with only refresh-tokens selected ---
	ops := buildPurgeOps(ds)
	selected := map[string]bool{"refresh-tokens": true}
	if err := runPurge(ctx, logger, ops, selected); err != nil {
		t.Fatalf("runPurge: %v", err)
	}

	// Expired refresh token should be purged
	_, err := ds.Token().GetRefreshTokenByHash(ctx, "hash-expired-filter")
	if err == nil {
		t.Error("expected error looking up expired refresh token, got nil")
	} else if !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("expected ErrInvalidGrant for expired RT, got: %v", err)
	}
}
