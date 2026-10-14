//go:build unix

package keyfile

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A reader that cannot write the lock file still takes the shared lock
// through a read-only handle, so it waits for a writer in another process;
// a lock file it cannot open at all is an error, not a reason to read
// without the lock.
func TestStore_ReadOnlyLockFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root opens files regardless of mode")
	}
	ctx := context.Background()
	dir := t.TempDir()
	s := newStore(t, dir)
	if err := s.CreateIfAbsent(ctx, boundKey(t)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	lockPath := filepath.Join(dir, ".lock")

	t.Run("read-only lock file is still honored", func(t *testing.T) {
		if err := os.Chmod(lockPath, 0o444); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(lockPath, 0o600) })
		holder, err := os.Open(lockPath) //nolint:gosec // test file
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer func() { _ = holder.Close() }()
		if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil { //nolint:gosec // test fd
			t.Fatalf("flock: %v", err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = s.LoadCurrent(ctx)
		}()
		select {
		case <-done:
			t.Fatal("LoadCurrent ran while another process held the exclusive lock")
		case <-time.After(100 * time.Millisecond):
		}
		_ = syscall.Flock(int(holder.Fd()), syscall.LOCK_UN) //nolint:gosec // test fd
		<-done
	})

	t.Run("unreadable lock file is an error", func(t *testing.T) {
		if err := os.Chmod(lockPath, 0o000); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(lockPath, 0o600) })
		if _, err := s.LoadCurrent(ctx); err == nil {
			t.Fatal("LoadCurrent succeeded without being able to open the lock file")
		}
	})
}
