package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/authplane/authserver/internal/adapters/storage"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// defaultPurgeTimeout caps a single `authserver purge` invocation. Operators with
// very large tables can override via --timeout (or pass 0 to disable).
const defaultPurgeTimeout = 10 * time.Minute

// purgeOp describes a single purge operation the CLI can run.
type purgeOp struct {
	name  string
	runFn func(ctx context.Context) (int64, error)
}

// purgeOpFactory pairs a target name with a builder that wires it to a datastore.
// This is the single source of truth — both --only validation and buildPurgeOps
// derive from this slice, so the two cannot drift apart.
//
// Entries must stay sorted by name so error messages and --help output are deterministic.
var purgeOpFactories = []purgeOpFactory{
	{"assertion-jti", func(ds output.DataStore) func(context.Context) (int64, error) {
		return uncounted(ds.AssertionJTI().PurgeExpired)
	}},
	{"connect-pending-states", func(ds output.DataStore) func(context.Context) (int64, error) {
		return func(ctx context.Context) (int64, error) {
			n, err := ds.ConnectPendingState().PurgeExpired(ctx, time.Now().UTC())
			return int64(n), err
		}
	}},
	// The unified consent_grants table has no expires_at column —
	// revocation is the way to clear a row, not expiration. No purge
	// target.
	{"dpop-nonces", func(ds output.DataStore) func(context.Context) (int64, error) {
		return uncounted(ds.DPoPNonce().PurgeExpired)
	}},
	{"jti", func(ds output.DataStore) func(context.Context) (int64, error) {
		return ds.Revocation().PurgeExpired
	}},
	{"machine-tokens", func(ds output.DataStore) func(context.Context) (int64, error) {
		return uncounted(ds.MachineToken().PurgeExpired)
	}},
	{"refresh-tokens", func(ds output.DataStore) func(context.Context) (int64, error) {
		return ds.Token().PurgeExpired
	}},
	{"sessions", func(ds output.DataStore) func(context.Context) (int64, error) {
		return ds.Session().DeleteExpired
	}},
}

type purgeOpFactory struct {
	name  string
	build func(output.DataStore) func(context.Context) (int64, error)
}

// purgeTargetNames returns the list of accepted --only values, derived from purgeOpFactories.
func purgeTargetNames() []string {
	names := make([]string, len(purgeOpFactories))
	for i, f := range purgeOpFactories {
		names[i] = f.name
	}
	return names
}

// parseOnly validates and returns the set of operations to run.
// If only is empty, all operations are selected.
func parseOnly(only string) (map[string]bool, error) {
	if only == "" {
		return nil, nil // nil means "all"
	}

	valid := make(map[string]bool, len(purgeOpFactories))
	for _, f := range purgeOpFactories {
		valid[f.name] = true
	}

	selected := make(map[string]bool)
	for name := range strings.SplitSeq(only, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !valid[name] {
			return nil, fmt.Errorf("unknown purge target %q (valid: %s)", name, validPurgeNamesList())
		}
		selected[name] = true
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("--only requires at least one target")
	}
	return selected, nil
}

func validPurgeNamesList() string {
	return strings.Join(purgeTargetNames(), ", ")
}

var (
	purgeOnlyFlag    string
	purgeTimeoutFlag time.Duration
)

var purgeCmd = &cobra.Command{
	Use:   "purge",
	Short: "Run a single pass of expired-data cleanup and exit",
	Long: `Purge removes expired rows from all purgeable tables in a single pass.
Designed to be scheduled via cron, systemd timer, or Kubernetes CronJob.

By default all tables are purged. Use --only to select specific targets:
  authserver purge --only=refresh-tokens,sessions

The command aborts after --timeout (default 10m) and on SIGINT/SIGTERM.
Pass --timeout=0 to disable the internal deadline.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		selected, err := parseOnly(purgeOnlyFlag)
		if err != nil {
			return err
		}

		cfg, err := loadConfig()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		obs := observability.NewNoop()
		ds, err := storage.Open(context.Background(), cfg.Storage, obs)
		if err != nil {
			return fmt.Errorf("open database: %w", err)
		}
		defer func() { _ = ds.Close() }()

		logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if purgeTimeoutFlag > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, purgeTimeoutFlag)
			defer cancel()
		}

		ops := buildPurgeOps(ds)
		return runPurge(ctx, logger, ops, selected)
	},
}

func init() {
	purgeCmd.Flags().StringVar(&purgeOnlyFlag, "only", "", "comma-separated list of targets to purge (default: all)")
	purgeCmd.Flags().DurationVar(&purgeTimeoutFlag, "timeout", defaultPurgeTimeout, "abort the run after this duration (0 = no timeout)")
}

// uncounted adapts a purge function that returns only error to the (int64, error) signature.
// Returns -1 on success to signal "no count available".
func uncounted(fn func(context.Context) error) func(context.Context) (int64, error) {
	return func(ctx context.Context) (int64, error) {
		if err := fn(ctx); err != nil {
			return 0, err
		}
		return -1, nil
	}
}

// buildPurgeOps returns all purge operations wired to the given datastore,
// derived from purgeOpFactories.
func buildPurgeOps(ds output.DataStore) []purgeOp {
	ops := make([]purgeOp, len(purgeOpFactories))
	for i, f := range purgeOpFactories {
		ops[i] = purgeOp{name: f.name, runFn: f.build(ds)}
	}
	return ops
}

// runPurge executes selected purge operations. If selected is nil, all operations run.
// Returns a non-nil error if any operation failed or the context was canceled.
//
// On context cancellation (SIGINT/SIGTERM or --timeout) the loop aborts after
// the in-flight op rather than firing further queries against a dead deadline.
func runPurge(ctx context.Context, logger *slog.Logger, ops []purgeOp, selected map[string]bool) error {
	var failed bool
	for _, op := range ops {
		if selected != nil && !selected[op.name] {
			continue
		}
		if err := ctx.Err(); err != nil {
			logger.Warn("purge aborted before op", "table", op.name, "reason", err)
			failed = true
			break
		}
		n, err := op.runFn(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				logger.Warn("purge interrupted", "table", op.name, "reason", err)
				failed = true
				break
			}
			logger.Error("purge failed", "table", op.name, "error", err)
			failed = true
			continue
		}
		if n < 0 {
			logger.Info("purge completed", "table", op.name)
		} else {
			logger.Info("purge completed", "table", op.name, "deleted", n)
		}
	}
	if failed {
		return fmt.Errorf("one or more purge operations failed")
	}
	return nil
}
