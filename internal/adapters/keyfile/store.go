// Package keyfile implements key storage using PEM files on disk.
package keyfile

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// Store implements output.KeyStore using PEM files in a directory.
//
// Layout:
//
//	<dir>/current.pem   — current signing key (PKCS8 private key)
//	<dir>/current.kid   — current key ID (plain text)
//	<dir>/current.alg   — current algorithm (plain text)
//	<dir>/previous.pem  — previous signing key (for JWKS during rotation)
//	<dir>/previous.kid  — previous key ID
//	<dir>/previous.alg  — previous algorithm
//	<dir>/.lock         — advisory lock file
//
// A key exists when its .pem file does. Reads take a shared lock and writes
// an exclusive one, both in-process and across processes on the same host
// (the server and `authserver admin key rotate`). Every file is written to a
// temporary file, synced and renamed into place, in an order that never
// leaves current.pem missing: see Save.
type Store struct {
	dir    string
	mu     sync.RWMutex
	logger *slog.Logger
	tracer trace.Tracer
}

var _ output.KeyStore = (*Store)(nil)

// tmpPattern names the temporary files a write leaves behind if it dies
// before renaming them; New removes them.
const tmpPattern = ".keyfile-*.tmp"

// New creates a keyfile Store rooted at the given directory.
// The directory is created if it does not exist.
func New(dir string, obs *observability.Provider) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil { //nolint:gosec // dir is the operator-configured key directory
		return nil, fmt.Errorf("create key directory: %w", err)
	}
	s := &Store{
		dir:    dir,
		logger: obs.Logger.With("component", "keyfile"),
		tracer: obs.Tracer,
	}
	if err := s.removeLeftovers(); err != nil {
		return nil, err
	}
	return s, nil
}

// removeLeftovers deletes temporary files from a write that died before
// renaming them. It holds the exclusive lock, so no live write owns them.
func (s *Store) removeLeftovers() error {
	unlock, err := s.lock(true)
	if err != nil {
		if isNotWritable(err) {
			// A key directory this process cannot write holds no leftovers
			// of its own writes, and could not remove any: serve its keys
			// read-only.
			return nil
		}
		return err
	}
	defer unlock()
	leftovers, err := filepath.Glob(filepath.Join(s.dir, tmpPattern))
	if err != nil {
		return fmt.Errorf("list leftover key files: %w", err)
	}
	for _, f := range leftovers {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove leftover key file: %w", err)
		}
	}
	return nil
}

// lock takes the in-process lock, then the cross-process one, and returns a
// function that releases both.
func (s *Store) lock(exclusive bool) (func(), error) {
	release := s.mu.RUnlock
	if exclusive {
		s.mu.Lock()
		release = s.mu.Unlock
	} else {
		s.mu.RLock()
	}
	unlockFile, err := fileLock(filepath.Join(s.dir, ".lock"), exclusive)
	if err != nil {
		release()
		return nil, err
	}
	return func() {
		unlockFile()
		release()
	}, nil
}

// LoadCurrent implements output.KeyStore.
func (s *Store) LoadCurrent(ctx context.Context) (*output.SigningKey, error) {
	_, span := s.tracer.Start(ctx, "Keyfile.LoadCurrent")
	defer span.End()

	key, err := s.loadLocked("current")
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return key, nil
}

// LoadPrevious implements output.KeyStore.
func (s *Store) LoadPrevious(ctx context.Context) (*output.SigningKey, error) {
	_, span := s.tracer.Start(ctx, "Keyfile.LoadPrevious")
	defer span.End()

	key, err := s.loadLocked("previous")
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return key, nil
}

func (s *Store) loadLocked(prefix string) (*output.SigningKey, error) {
	unlock, err := s.lock(false)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.loadKey(prefix)
}

// Save makes key current and the old current key previous, in this order:
//
//  1. Write the new key's three files to temporary files and sync them.
//  2. Read the current key's files, if there is a current key.
//  3. Delete previous.pem.
//  4. Write previous.kid, previous.alg, then previous.pem with the current
//     key's content.
//  5. Rename the new current.kid, current.alg, then current.pem into place.
//
// A crash, or a reader in a process that ignores the lock, at any point
// sees one of: the state before; no previous key (step 3 or partway through
// 4, and that key was being retired anyway); previous equal to current
// (after 4; the JWKS drops the duplicate); the old key under the new kid
// (after current.kid, which still verifies through the JWKS); or, only when
// the algorithm changes, a key whose type disagrees with its .alg file. That
// key fails to load, so nothing signs until the next rotation, but the JWKS
// still publishes previous, and that rotation replaces it without moving it
// to previous. current.pem is never missing, so a crash never makes a new
// key appear.
func (s *Store) Save(ctx context.Context, key *output.SigningKey) error {
	ctx, span := s.tracer.Start(ctx, "Keyfile.Save")
	defer span.End()

	unlock, err := s.lock(true)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	defer unlock()

	if err := s.save(ctx, key); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	s.logger.InfoContext(ctx, "saved signing key", "kid", key.KeyID, "alg", key.Algorithm)
	return nil
}

func (s *Store) save(ctx context.Context, key *output.SigningKey) error {
	staged, err := s.stage(key)
	if err != nil {
		return err
	}
	defer staged.cleanup()

	cur, err := s.readFiles("current")
	if err != nil && !errors.Is(err, errUnusableKey) {
		return err
	}
	if err == nil && cur != nil {
		_, err = s.loadKey("current")
		if err != nil && !errors.Is(err, errUnusableKey) {
			return err
		}
	}
	if err != nil {
		// An unusable current key (a crash during an algorithm change, or
		// files half written or edited by hand) never signed a token that
		// verifies, and previous is the key outstanding tokens need: keep
		// previous and replace current.
		s.logger.WarnContext(ctx, "replacing an unusable current key; previous kept", "error", err)
		cur = nil
	}
	if cur != nil {
		if err := os.Remove(filepath.Join(s.dir, "previous.pem")); err != nil && !os.IsNotExist(err) { //nolint:gosec // fixed name in the configured key directory
			return fmt.Errorf("remove previous.pem: %w", err)
		}
		if err := s.syncDir(); err != nil {
			return err
		}
		for _, ext := range []string{".kid", ".alg", ".pem"} {
			if err := s.writeFile("previous"+ext, cur[ext]); err != nil {
				return err
			}
		}
		s.logger.InfoContext(ctx, "rotated current key to previous")
	}
	return staged.commit()
}

// CreateIfAbsent writes key as the current key only when there is none.
func (s *Store) CreateIfAbsent(ctx context.Context, key *output.SigningKey) error {
	ctx, span := s.tracer.Start(ctx, "Keyfile.CreateIfAbsent")
	defer span.End()

	unlock, err := s.lock(true)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	defer unlock()

	present, err := exists(filepath.Join(s.dir, "current.pem"))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if present {
		return nil
	}
	staged, err := s.stage(key)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	defer staged.cleanup()
	if err := staged.commit(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	s.logger.InfoContext(ctx, "created first signing key", "kid", key.KeyID, "alg", key.Algorithm)
	return nil
}

// ListActive returns all active signing keys (current + previous if exists).
func (s *Store) ListActive(ctx context.Context) ([]*output.SigningKey, error) {
	ctx, span := s.tracer.Start(ctx, "Keyfile.ListActive")
	defer span.End()

	unlock, err := s.lock(false)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	defer unlock()

	keys := []*output.SigningKey{}
	for _, prefix := range []string{"current", "previous"} {
		key, err := s.loadKey(prefix)
		if errors.Is(err, errUnusableKey) {
			// An unusable key (see errUnusableKey) verifies nothing, but the
			// other key still can: publish that one.
			s.logger.WarnContext(ctx, "skipping an unusable signing key; run `authserver admin key rotate` to replace it", "key", prefix, "error", err)
			continue
		}
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
		if key != nil {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// stagedKey is a new current key written to synced temporary files and not
// yet renamed into place.
type stagedKey struct {
	s     *Store
	files map[string]string // extension → temporary path
}

// stage writes key's three files to temporary files in the key directory.
func (s *Store) stage(key *output.SigningKey) (*stagedKey, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	content := map[string][]byte{
		".kid": []byte(key.KeyID),
		".alg": []byte(key.Algorithm),
		".pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
	}
	st := &stagedKey{s: s, files: map[string]string{}}
	for _, ext := range []string{".kid", ".alg", ".pem"} {
		tmp, err := s.writeTemp(content[ext])
		if err != nil {
			st.cleanup()
			return nil, err
		}
		st.files[ext] = tmp
	}
	return st, nil
}

// commit renames the staged files into place as current.kid, current.alg
// and current.pem, in that order, syncing the directory after each.
func (st *stagedKey) commit() error {
	for _, ext := range []string{".kid", ".alg", ".pem"} {
		if err := os.Rename(st.files[ext], filepath.Join(st.s.dir, "current"+ext)); err != nil { //nolint:gosec // fixed names in the configured key directory
			return fmt.Errorf("install current%s: %w", ext, err)
		}
		delete(st.files, ext)
		// Sync after each rename: the order is what makes every crash state
		// safe, and not every filesystem keeps it otherwise.
		if err := st.s.syncDir(); err != nil {
			return err
		}
	}
	return nil
}

// cleanup removes any staged file not yet renamed into place.
func (st *stagedKey) cleanup() {
	for _, tmp := range st.files {
		_ = os.Remove(tmp)
	}
}

// writeFile replaces name atomically: a temporary file, synced, renamed over
// it, then the directory synced.
func (s *Store) writeFile(name string, data []byte) error {
	tmp, err := s.writeTemp(data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, name)); err != nil { //nolint:gosec // fixed names in the configured key directory
		_ = os.Remove(tmp) //nolint:gosec // a temporary file this store created
		return fmt.Errorf("install %s: %w", name, err)
	}
	return s.syncDir()
}

// writeTemp writes data to a new synced temporary file in the key directory
// and returns its path.
func (s *Store) writeTemp(data []byte) (string, error) {
	f, err := os.CreateTemp(s.dir, tmpPattern)
	if err != nil {
		return "", fmt.Errorf("create temporary key file: %w", err)
	}
	path := f.Name()
	fail := func(step string, err error) (string, error) {
		_ = f.Close()
		_ = os.Remove(path) //nolint:gosec // a temporary file this store created
		return "", fmt.Errorf("%s temporary key file: %w", step, err)
	}
	if err := f.Chmod(0o600); err != nil {
		return fail("chmod", err)
	}
	if _, err := f.Write(data); err != nil {
		return fail("write", err)
	}
	if err := f.Sync(); err != nil {
		return fail("sync", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path) //nolint:gosec // a temporary file this store created
		return "", fmt.Errorf("close temporary key file: %w", err)
	}
	return path, nil
}

// syncDir makes the directory's renames durable.
func (s *Store) syncDir() error {
	d, err := os.Open(s.dir) //nolint:gosec // the configured key directory
	if err != nil {
		return fmt.Errorf("open key directory: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync key directory: %w", err)
	}
	return nil
}

// readFiles returns the raw .kid, .alg and .pem content of the key with this
// prefix, or nil when its .pem file does not exist.
func (s *Store) readFiles(prefix string) (map[string][]byte, error) {
	present, err := exists(filepath.Join(s.dir, prefix+".pem"))
	if err != nil || !present {
		return nil, err
	}
	out := map[string][]byte{}
	for _, ext := range []string{".kid", ".alg", ".pem"} {
		data, err := os.ReadFile(filepath.Join(s.dir, prefix+ext)) //nolint:gosec // path is constructed from validated prefix within configured key directory
		if os.IsNotExist(err) {
			// The .pem exists but a companion file does not: a key half
			// written by an older version, or edited by hand.
			return nil, fmt.Errorf("%w: %s.pem without %s%s", errUnusableKey, prefix, prefix, ext)
		}
		if err != nil {
			return nil, fmt.Errorf("read %s%s: %w", prefix, ext, err)
		}
		out[ext] = data
	}
	return out, nil
}

func (s *Store) loadKey(prefix string) (*output.SigningKey, error) {
	files, err := s.readFiles(prefix)
	if err != nil || files == nil {
		return nil, err
	}
	kid := strings.TrimSpace(string(files[".kid"]))
	alg := strings.TrimSpace(string(files[".alg"]))

	block, _ := pem.Decode(files[".pem"])
	if block == nil {
		return nil, fmt.Errorf("%w: decode %s.pem: no PEM block found", errUnusableKey, prefix)
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse %s.pem: %w", errUnusableKey, prefix, err)
	}

	sk := &output.SigningKey{Algorithm: alg, KeyID: kid}
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		sk.PrivateKey, sk.PublicKey = k, &k.PublicKey
	case *rsa.PrivateKey:
		sk.PrivateKey, sk.PublicKey = k, &k.PublicKey
	default:
		return nil, fmt.Errorf("%w: unsupported key type: %T", errUnusableKey, priv)
	}
	if err := checkAlgorithm(sk); err != nil {
		return nil, fmt.Errorf("%s key: %w", prefix, err)
	}
	return sk, nil
}

// errUnusableKey reports key files that exist but cannot be used: a
// companion file missing, PEM that does not decode or parse, or a key type
// that does not match its algorithm. I/O errors are not unusable keys.
var errUnusableKey = errors.New("unusable signing key files")

// errAlgorithmMismatch reports a key whose type cannot produce its .alg
// file's algorithm. Signing with it would issue tokens that never verify.
var errAlgorithmMismatch = fmt.Errorf("%w: key type does not match its algorithm", errUnusableKey)

func checkAlgorithm(sk *output.SigningKey) error {
	switch sk.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		if sk.Algorithm == "ES256" {
			return nil
		}
	case *rsa.PrivateKey:
		if sk.Algorithm == "RS256" {
			return nil
		}
	}
	return fmt.Errorf("%w: %T with %q", errAlgorithmMismatch, sk.PrivateKey, sk.Algorithm)
}

// exists reports whether path exists. Only "not found" means absent: any
// other stat error is returned, so an unreadable or looping key file is never
// mistaken for no key and overwritten.
func exists(path string) (bool, error) {
	_, err := os.Stat(path) //nolint:gosec // paths in the configured key directory
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("stat %s: %w", filepath.Base(path), err)
}
