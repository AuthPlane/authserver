//go:build !unix

package keyfile

import (
	"errors"
	"io/fs"
)

// fileLock is a no-op where flock is unavailable. Releases are built only for
// Linux and macOS; elsewhere the in-process lock still applies.
func fileLock(string, bool) (func(), error) { return func() {}, nil }

// isNotWritable reports an error from creating or opening a file for writing
// in a directory this process cannot write.
func isNotWritable(err error) bool { return errors.Is(err, fs.ErrPermission) }
