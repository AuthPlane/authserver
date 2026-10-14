//go:build unix

package keyfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// fileLock takes an advisory flock on path: shared for readers, exclusive
// for writers. It coordinates the server with another process on the same
// host, such as `authserver admin key rotate` run in the server's container.
// The returned function releases the lock.
//
// A reader that cannot open the lock file for writing (keys mounted
// read-only, or written by another user) takes the shared lock through a
// read-only handle; the file is created readable for that reason, inside a
// key directory only its owner can enter. Only when there is no lock file and
// none can be created does a reader go without one: nothing can then write
// keys there through this store. A writer always needs the lock, and a lock
// file that exists but cannot be opened is an error.
func fileLock(path string, exclusive bool) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644) //nolint:gosec // an empty lock file in the owner-only key directory
	if err != nil && !exclusive && isNotWritable(err) {
		f, err = os.Open(path) //nolint:gosec // path is the key directory's lock file
		if err != nil && os.IsNotExist(err) {
			return func() {}, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	for {
		err = syscall.Flock(int(f.Fd()), how) //nolint:gosec // a file descriptor fits in an int
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:gosec // a file descriptor fits in an int
		_ = f.Close()
	}, nil
}

// isNotWritable reports an error from creating or opening a file for writing
// in a directory this process cannot write.
func isNotWritable(err error) bool {
	return errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EROFS)
}
