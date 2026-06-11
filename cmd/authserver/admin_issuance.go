package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/authplane/authserver/internal/admin/dto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
)

// defaultIssuanceSinceWindow matches the HTTP admin layer's 24h default
// for ?since=. The CLI honors the same value when --since is omitted on
// --user / --client list forms; the --jti list form ignores --since
// entirely (point-query, not windowed).
const defaultIssuanceSinceWindow = 24 * time.Hour

// maxIssuanceSinceWindow caps the windowed list query at 30 days,
// matching the HTTP admin layer. Bigger windows pull a lot of rows and
// shouldn't go through the operator surface — operators querying that
// far back should hit the DB / OTel exports directly.
const maxIssuanceSinceWindow = 30 * 24 * time.Hour

// issuanceCmd is the parent for issuance management subcommands.
// Implements the design's forensic + revoke surface at the CLI layer.
var issuanceCmd = &cobra.Command{
	Use:   "issuance",
	Short: "Inspect + revoke issuances (per-token forensic records)",
	Args:  cobra.NoArgs, // unknown subcommand → loud error (see admin.go)
	RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
}

// --- issuance list ---

var issuanceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List issuances (filter by --user / --client / --jti / --resource)",
	Long: "List issuances filtered by any combination of --user, --client, " +
		"--resource, or --jti (at least one is required). --since accepts " +
		"Go durations plus 'd' (days) and 'w' (weeks) suffixes; default " +
		"24h, max 30d. --jti is a point-query: --since is ignored, and " +
		"other filters narrow the single-row result.",
	RunE: func(cmd *cobra.Command, args []string) error {
		userID, _ := cmd.Flags().GetString("user")
		clientID, _ := cmd.Flags().GetString("client")
		jti, _ := cmd.Flags().GetString("jti")
		resourceID, _ := cmd.Flags().GetString("resource")

		if nonEmptyCount(userID, clientID, jti, resourceID) == 0 {
			return fmt.Errorf("requires at least one of: --user, --client, --jti, --resource")
		}

		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		jsonOut, _ := cmd.Flags().GetBool("json")
		limit, _ := cmd.Flags().GetInt("limit")
		if limit <= 0 {
			return fmt.Errorf("--limit must be positive")
		}

		var rows []*resource.Issuance
		var since time.Time

		if jti != "" {
			// JTI is a single-row point-query — --since is silently ignored.
			// When other filters are supplied alongside --jti they narrow
			// the result so a stale jti from a different tuple cannot leak
			// through.
			i, getErr := env.issuanceAdminSvc.GetByJTI(cmd.Context(), jti)
			if getErr != nil {
				return fmt.Errorf("get issuance by jti: %w", getErr)
			}
			if i != nil && issuanceMatchesFilter(i, userID, clientID, resourceID) {
				rows = []*resource.Issuance{i}
			}
		} else {
			since, err = computeSince(cmd)
			if err != nil {
				return err
			}
			// Pick the indexed dimension that drives the DB query (user >
			// client > resource). Remaining filters apply in memory — the
			// driving dimension is zeroed out so its own predicate is
			// skipped (rows already match it via the indexed lookup).
			rUser, rClient, rResource := userID, clientID, resourceID
			switch {
			case userID != "":
				rows, err = env.issuanceAdminSvc.ListForUser(cmd.Context(), userID, since)
				rUser = ""
			case clientID != "":
				rows, err = env.issuanceAdminSvc.ListForActor(cmd.Context(), clientID, since)
				rClient = ""
			case resourceID != "":
				rows, err = env.issuanceAdminSvc.ListForResource(cmd.Context(), resourceID, since)
				rResource = ""
			}
			if err != nil {
				return fmt.Errorf("list issuances: %w", err)
			}
			rows = filterIssuances(rows, rUser, rClient, rResource)
		}

		if len(rows) > limit {
			rows = rows[:limit]
		}

		if jsonOut {
			return writeJSON(cmd.OutOrStdout(), dto.IssuanceListResponse{
				Issuances: dto.IssuancesToViews(rows),
				Since:     formatSince(since),
				Count:     len(rows),
			})
		}

		out := cmd.OutOrStdout()
		_, _ = fmt.Fprintf(out, "issuances (%d) since=%s:\n", len(rows), formatSince(since))
		for _, i := range rows {
			_, _ = fmt.Fprintf(out, "  id=%s jti=%s subject_user_id=%s client_id=%s resource_id=%s backend_kind=%s issued_at=%s expires_at=%s%s\n",
				i.ID, i.JTI, i.SubjectUserID, i.ClientID, i.ResourceID,
				i.BackendKind, i.IssuedAt.UTC().Format(time.RFC3339),
				i.ExpiresAt.UTC().Format(time.RFC3339),
				revokedSuffix(i.RevokedAt))
		}
		return nil
	},
}

// --- issuance get ---

var issuanceGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get an issuance by id (issuance UUID)",
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetString("id")
		if id == "" {
			return fmt.Errorf("--id is required")
		}

		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		i, err := env.issuanceAdminSvc.GetByID(cmd.Context(), id)
		if err != nil {
			if errors.Is(err, domain.ErrIssuanceNotFound) {
				return fmt.Errorf("issuance not found: %s", id)
			}
			return fmt.Errorf("get issuance: %w", err)
		}

		jsonOut, _ := cmd.Flags().GetBool("json")
		if jsonOut {
			return writeJSON(cmd.OutOrStdout(), dto.IssuanceToView(i))
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"id=%s jti=%s subject_user_id=%s client_id=%s resource_id=%s backend_kind=%s scopes=%v issued_at=%s expires_at=%s%s\n",
			i.ID, i.JTI, i.SubjectUserID, i.ClientID, i.ResourceID,
			i.BackendKind, i.Scopes,
			i.IssuedAt.UTC().Format(time.RFC3339),
			i.ExpiresAt.UTC().Format(time.RFC3339),
			revokedSuffix(i.RevokedAt))
		return nil
	},
}

// --- issuance revoke ---

var issuanceRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke an issuance (soft-delete; idempotent)",
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetString("id")
		if id == "" {
			return fmt.Errorf("--id is required")
		}

		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		if err := env.issuanceAdminSvc.Revoke(cmd.Context(), id); err != nil {
			return fmt.Errorf("revoke issuance: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "issuance revoked: id=%s\n", id)
		return nil
	},
}

// computeSince returns the effective window-start time for windowed list
// forms: clock-now minus --since (default 24h), capped at 30 days.
func computeSince(cmd *cobra.Command) (time.Time, error) {
	raw, _ := cmd.Flags().GetString("since")
	now := time.Now().UTC()
	if raw == "" {
		return now.Add(-defaultIssuanceSinceWindow), nil
	}
	d, err := parseDurationExt(raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("--since: %w", err)
	}
	if d > maxIssuanceSinceWindow {
		return time.Time{}, fmt.Errorf("--since exceeds 30-day cap; narrow the query or query the DB directly")
	}
	return now.Add(-d), nil
}

// formatSince returns the RFC3339 representation of t, or the empty string
// for the zero time (the JTI point-query path leaves since unset).
func formatSince(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// nonEmptyCount returns how many of vals are non-empty. Used for the
// "at least one filter required" check on the issuance list command.
func nonEmptyCount(vals ...string) int {
	n := 0
	for _, v := range vals {
		if v != "" {
			n++
		}
	}
	return n
}

// issuanceMatchesFilter reports whether i satisfies every non-empty filter.
// Empty filters are wildcards. Mirrors api/admin/issuances.go::issuanceMatches
// so the CLI and HTTP surfaces apply identical post-filter semantics.
func issuanceMatchesFilter(i *resource.Issuance, userID, clientID, resourceID string) bool {
	if userID != "" && i.SubjectUserID != userID {
		return false
	}
	if clientID != "" && i.ClientID != clientID {
		return false
	}
	if resourceID != "" && i.ResourceID != resourceID {
		return false
	}
	return true
}

// filterIssuances returns the rows that match every non-empty filter.
// Empty filters are wildcards. Used after the indexed DB query to apply
// any remaining cross-dimension predicates.
func filterIssuances(rows []*resource.Issuance, userID, clientID, resourceID string) []*resource.Issuance {
	out := rows[:0]
	for _, i := range rows {
		if issuanceMatchesFilter(i, userID, clientID, resourceID) {
			out = append(out, i)
		}
	}
	return out
}

func init() {
	issuanceListCmd.Flags().String("user", "", "Filter issuances by subject user id")
	issuanceListCmd.Flags().String("client", "", "Filter issuances by client id (actor)")
	issuanceListCmd.Flags().String("resource", "", "Filter issuances by resource id")
	issuanceListCmd.Flags().String("jti", "", "Look up a single issuance by JTI (incident response; --since ignored)")
	issuanceListCmd.Flags().String("since", "", "Lookback window (default 24h, max 30d). Accepts Go durations plus d/w suffixes (e.g. 7d, 2w).")
	issuanceListCmd.Flags().Int("limit", 500, "Maximum rows returned (1..5000)")
	issuanceListCmd.Flags().Bool("json", false, "Emit JSON instead of human-readable lines")

	issuanceGetCmd.Flags().String("id", "", "Issuance UUID (required)")
	issuanceGetCmd.Flags().Bool("json", false, "Emit JSON instead of human-readable lines")

	issuanceRevokeCmd.Flags().String("id", "", "Issuance UUID (required)")

	issuanceCmd.AddCommand(issuanceListCmd)
	issuanceCmd.AddCommand(issuanceGetCmd)
	issuanceCmd.AddCommand(issuanceRevokeCmd)
}
