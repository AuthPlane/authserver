package keyfile

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// boundKey returns a key whose kid is derived from its public key, so a
// reader can tell whether the kid, algorithm and key it loaded belong
// together: a torn read pairs one key's kid with another key's material.
func boundKey(t testing.TB) *output.SigningKey {
	t.Helper()
	kp, err := crypto.GenerateKeyPair("ES256", "")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sk := &output.SigningKey{PrivateKey: kp.PrivateKey, PublicKey: kp.PublicKey, Algorithm: "ES256"}
	sk.KeyID = kidOf(t, sk)
	return sk
}

func kidOf(t testing.TB, sk *output.SigningKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(sk.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}

func checkBound(t testing.TB, sk *output.SigningKey) error {
	if sk == nil {
		return nil
	}
	if want := kidOf(t, sk); sk.KeyID != want {
		return errors.New("torn key: kid " + sk.KeyID + " does not belong to the key material (" + want + ")")
	}
	return nil
}

func newStore(t testing.TB, dir string) *Store {
	t.Helper()
	s, err := New(dir, observability.NewNoop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// Two store instances on one directory (two processes, in effect) racing
// first use create exactly one key, and every caller reads that key.
func TestStore_ConcurrentFirstUse_OneKey(t *testing.T) {
	dir := t.TempDir()
	stores := []*Store{newStore(t, dir), newStore(t, dir)}
	const callers = 640
	kids := make([]string, callers)
	errs := make([]error, callers)
	var start, done sync.WaitGroup
	start.Add(1)
	for i := 0; i < callers; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			s := stores[i%2]
			if err := s.CreateIfAbsent(context.Background(), boundKey(t)); err != nil {
				errs[i] = err
				return
			}
			cur, err := s.LoadCurrent(context.Background())
			if err == nil && cur == nil {
				err = errors.New("no current key after CreateIfAbsent")
			}
			if err == nil {
				err = checkBound(t, cur)
			}
			if err != nil {
				errs[i] = err
				return
			}
			kids[i] = cur.KeyID
		}(i)
	}
	start.Done()
	done.Wait()
	for i := range kids {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if kids[i] != kids[0] {
			t.Fatalf("caller %d read kid %s, caller 0 read %s", i, kids[i], kids[0])
		}
	}
	if prev, err := stores[0].LoadPrevious(context.Background()); err != nil || prev != nil {
		t.Errorf("LoadPrevious = %v, %v; want none: first use never rotates", prev, err)
	}
}

// Readers never see a torn key while another store instance rotates.
func TestStore_RotationsUnderConcurrentReaders(t *testing.T) {
	dir := t.TempDir()
	writer, reader := newStore(t, dir), newStore(t, dir)
	if err := writer.CreateIfAbsent(context.Background(), boundKey(t)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	stop := make(chan struct{})
	readErr := make(chan error, 1)
	var readers sync.WaitGroup
	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := readConsistently(t, reader); err != nil {
					select {
					case readErr <- err:
					default:
					}
					return
				}
			}
		}()
	}
	for i := 0; i < 400; i++ {
		if err := writer.Save(context.Background(), boundKey(t)); err != nil {
			close(stop)
			t.Fatalf("rotation %d: %v", i, err)
		}
	}
	close(stop)
	readers.Wait()
	select {
	case err := <-readErr:
		t.Fatal(err)
	default:
	}
}

// readConsistently loads current, previous and the active set and checks
// each key is whole and current is always present.
func readConsistently(t testing.TB, s *Store) error {
	ctx := context.Background()
	cur, err := s.LoadCurrent(ctx)
	if err != nil {
		return err
	}
	if cur == nil {
		return errors.New("current key missing during rotation")
	}
	if err = checkBound(t, cur); err != nil {
		return err
	}
	prev, err := s.LoadPrevious(ctx)
	if err != nil {
		return err
	}
	if err = checkBound(t, prev); err != nil {
		return err
	}
	active, err := s.ListActive(ctx)
	if err != nil {
		return err
	}
	for _, k := range active {
		if err := checkBound(t, k); err != nil {
			return err
		}
	}
	return nil
}

// TestHelperRotate is not a test: run as a child process by
// TestStore_CrossProcessRotation, it rotates the key in KEYFILE_HELPER_DIR
// KEYFILE_HELPER_ROTATIONS times, as `authserver admin key rotate` would
// next to a running server.
func TestHelperRotate(t *testing.T) {
	dir := os.Getenv("KEYFILE_HELPER_DIR")
	if dir == "" {
		t.Skip("helper process only")
	}
	n, err := strconv.Atoi(os.Getenv("KEYFILE_HELPER_ROTATIONS"))
	if err != nil {
		t.Fatalf("rotations: %v", err)
	}
	s := newStore(t, dir)
	for i := 0; i < n; i++ {
		if err := s.Save(context.Background(), boundKey(t)); err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
	}
}

// A second OS process rotating the key while this one reads: the advisory
// lock keeps every read whole.
func TestStore_CrossProcessRotation(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir)
	if err := s.CreateIfAbsent(context.Background(), boundKey(t)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHelperRotate$", "-test.count=1") //nolint:gosec // re-runs this test binary
	cmd.Env = append(os.Environ(), "KEYFILE_HELPER_DIR="+dir, "KEYFILE_HELPER_ROTATIONS=200")
	out := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	reads := 0
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("helper process: %v\n%s", err, out.String())
			}
			if reads == 0 {
				t.Fatal("no reads overlapped the helper's rotations")
			}
			return
		default:
		}
		if err := readConsistently(t, s); err != nil {
			_ = cmd.Process.Kill()
			t.Fatalf("read %d while another process rotates: %v", reads, err)
		}
		reads++
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

// The states a crash can leave at each step of Save, built on disk: each
// loads as the Save comment says, and current.pem is never missing.
func TestStore_CrashPoints(t *testing.T) {
	ctx := context.Background()
	old, next := boundKey(t), boundKey(t)
	type state struct {
		name     string
		build    func(t *testing.T, dir string, s *Store)
		wantCur  string
		wantPrev string // "" = none
		wantErr  bool
	}
	writeAs := func(t *testing.T, s *Store, prefix string, k *output.SigningKey, exts ...string) {
		t.Helper()
		st, err := s.stage(k)
		if err != nil {
			t.Fatalf("stage: %v", err)
		}
		defer st.cleanup()
		for _, ext := range exts {
			if err := os.Rename(st.files[ext], filepath.Join(s.dir, prefix+ext)); err != nil {
				t.Fatalf("install %s%s: %v", prefix, ext, err)
			}
			delete(st.files, ext)
		}
	}
	all := []string{".kid", ".alg", ".pem"}
	states := []state{
		{"before the rotation", func(t *testing.T, _ string, s *Store) {
			writeAs(t, s, "current", old, all...)
		}, old.KeyID, "", false},
		{"previous.pem deleted (step 3)", func(t *testing.T, _ string, s *Store) {
			writeAs(t, s, "current", old, all...)
		}, old.KeyID, "", false},
		{"previous.kid and .alg written, no .pem (step 4)", func(t *testing.T, _ string, s *Store) {
			writeAs(t, s, "current", old, all...)
			writeAs(t, s, "previous", old, ".kid", ".alg")
		}, old.KeyID, "", false},
		{"previous equals current (after step 4)", func(t *testing.T, _ string, s *Store) {
			writeAs(t, s, "current", old, all...)
			writeAs(t, s, "previous", old, all...)
		}, old.KeyID, old.KeyID, false},
		{"new current.kid, old current.alg and .pem (step 5)", func(t *testing.T, _ string, s *Store) {
			writeAs(t, s, "current", old, all...)
			writeAs(t, s, "previous", old, all...)
			writeAs(t, s, "current", next, ".kid")
		}, next.KeyID, old.KeyID, false},
		{"rotation complete", func(t *testing.T, _ string, s *Store) {
			writeAs(t, s, "previous", old, all...)
			writeAs(t, s, "current", next, all...)
		}, next.KeyID, old.KeyID, false},
	}
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			dir := t.TempDir()
			s := newStore(t, dir)
			st.build(t, dir, s)
			cur, err := s.LoadCurrent(ctx)
			if err != nil || cur == nil || cur.KeyID != st.wantCur {
				t.Fatalf("LoadCurrent = %v, %v; want kid %s", cur, err, st.wantCur)
			}
			prev, err := s.LoadPrevious(ctx)
			if err != nil {
				t.Fatalf("LoadPrevious: %v", err)
			}
			got := ""
			if prev != nil {
				got = prev.KeyID
			}
			if got != st.wantPrev {
				t.Fatalf("previous kid = %q, want %q", got, st.wantPrev)
			}
		})
	}

	t.Run("algorithm changed, new .alg over the old key fails to load", func(t *testing.T) {
		s := newStore(t, t.TempDir())
		writeAs(t, s, "current", old, all...)
		if err := os.WriteFile(filepath.Join(s.dir, "current.alg"), []byte("RS256"), 0o600); err != nil {
			t.Fatalf("write alg: %v", err)
		}
		if _, err := s.LoadCurrent(ctx); !errors.Is(err, errAlgorithmMismatch) {
			t.Fatalf("LoadCurrent err = %v, want errAlgorithmMismatch", err)
		}
	})
}

// A write that died before renaming leaves temporary files; opening the
// store removes them and leaves the keys alone.
func TestNew_RemovesLeftoverTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir)
	if err := s.CreateIfAbsent(context.Background(), boundKey(t)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	leftover, err := s.writeTemp([]byte("partial"))
	if err != nil {
		t.Fatalf("writeTemp: %v", err)
	}
	newStore(t, dir)
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Errorf("leftover %s still present (stat err %v)", leftover, err)
	}
	if cur, err := s.LoadCurrent(context.Background()); err != nil || cur == nil {
		t.Errorf("LoadCurrent after reopening = %v, %v; want the key kept", cur, err)
	}
}

// A crash during a rotation that changed the algorithm leaves current's
// .alg over the other key type. Nothing can sign with it, but the JWKS
// still publishes previous, and the next rotation replaces current while
// keeping previous: tokens signed with previous keep verifying throughout.
func TestStore_CrashDuringAlgorithmChange_KeepsPreviousPublished(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, t.TempDir())
	k1 := boundKey(t)
	if err := s.CreateIfAbsent(ctx, k1); err != nil {
		t.Fatalf("seed: %v", err)
	}
	k2 := boundKey(t)
	if err := s.Save(ctx, k2); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// The crash state: an RS256 rotation renamed current.kid and
	// current.alg but not current.pem.
	if err := os.WriteFile(filepath.Join(s.dir, "current.alg"), []byte("RS256"), 0o600); err != nil {
		t.Fatalf("write alg: %v", err)
	}
	if _, err := s.LoadCurrent(ctx); !errors.Is(err, errAlgorithmMismatch) {
		t.Fatalf("LoadCurrent err = %v, want errAlgorithmMismatch", err)
	}
	active, err := s.ListActive(ctx)
	if err != nil || len(active) != 1 || active[0].KeyID != k1.KeyID {
		t.Fatalf("ListActive = %v, %v; want previous (%s) still published", active, err, k1.KeyID)
	}

	k3 := boundKey(t)
	if err = s.Save(ctx, k3); err != nil {
		t.Fatalf("rotate after the crash: %v", err)
	}
	cur, err := s.LoadCurrent(ctx)
	if err != nil || cur.KeyID != k3.KeyID {
		t.Fatalf("LoadCurrent = %v, %v; want %s", cur, err, k3.KeyID)
	}
	prev, err := s.LoadPrevious(ctx)
	if err != nil || prev == nil || prev.KeyID != k1.KeyID {
		t.Fatalf("LoadPrevious = %v, %v; want %s kept", prev, err, k1.KeyID)
	}
}

// Other unusable current keys (a companion file missing, a PEM that does not
// parse) are handled the same way: the JWKS publishes previous, and the next
// rotation replaces current and keeps previous.
func TestStore_UnusableCurrent_ReplacedAndPreviousKept(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"current.kid missing": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "current.kid")); err != nil {
				t.Fatalf("remove: %v", err)
			}
		},
		"current.pem has no PEM block": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "current.pem"), []byte("not a key"), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
		},
		"current.pem does not parse": func(t *testing.T, dir string) {
			garbage := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not DER")})
			if err := os.WriteFile(filepath.Join(dir, "current.pem"), garbage, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
		},
		"current.pem holds an unsupported key type": func(t *testing.T, dir string) {
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			der, err := x509.MarshalPKCS8PrivateKey(priv)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "current.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := newStore(t, t.TempDir())
			k1, k2 := boundKey(t), boundKey(t)
			if err := s.CreateIfAbsent(ctx, k1); err != nil {
				t.Fatalf("seed: %v", err)
			}
			if err := s.Save(ctx, k2); err != nil {
				t.Fatalf("rotate: %v", err)
			}
			breakIt(t, s.dir)

			if _, err := s.LoadCurrent(ctx); !errors.Is(err, errUnusableKey) {
				t.Fatalf("LoadCurrent err = %v, want errUnusableKey", err)
			}
			if active, err := s.ListActive(ctx); err != nil || len(active) != 1 || active[0].KeyID != k1.KeyID {
				t.Fatalf("ListActive = %v, %v; want previous (%s) still published", active, err, k1.KeyID)
			}
			k3 := boundKey(t)
			if err := s.Save(ctx, k3); err != nil {
				t.Fatalf("rotate after breakage: %v", err)
			}
			if prev, err := s.LoadPrevious(ctx); err != nil || prev == nil || prev.KeyID != k1.KeyID {
				t.Fatalf("LoadPrevious = %v, %v; want %s kept", prev, err, k1.KeyID)
			}
		})
	}
}

// An I/O failure is not an unusable key: reads and rotations fail, and
// nothing is replaced or moved, so no key is lost to a transient error or a
// permission problem.
func TestStore_IOErrors_FailWithoutReplacingKeys(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"current.kid unreadable": func(t *testing.T, dir string) {
			if os.Getuid() == 0 {
				t.Skip("root reads files regardless of mode")
			}
			if err := os.Chmod(filepath.Join(dir, "current.kid"), 0); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, "current.kid"), 0o600) })
		},
		"current.kid is a directory": func(t *testing.T, dir string) {
			p := filepath.Join(dir, "current.kid")
			if err := os.Remove(p); err != nil {
				t.Fatalf("remove: %v", err)
			}
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
		},
		"current.pem is a symlink loop": func(t *testing.T, dir string) {
			p := filepath.Join(dir, "current.pem")
			if err := os.Remove(p); err != nil {
				t.Fatalf("remove: %v", err)
			}
			if err := os.Symlink(p, p); err != nil {
				t.Fatalf("symlink: %v", err)
			}
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := newStore(t, t.TempDir())
			k1, k2 := boundKey(t), boundKey(t)
			if err := s.CreateIfAbsent(ctx, k1); err != nil {
				t.Fatalf("seed: %v", err)
			}
			if err := s.Save(ctx, k2); err != nil {
				t.Fatalf("rotate: %v", err)
			}
			breakIt(t, s.dir)

			if _, err := s.LoadCurrent(ctx); err == nil || errors.Is(err, errUnusableKey) {
				t.Errorf("LoadCurrent err = %v, want an I/O error, not an unusable key", err)
			}
			if _, err := s.ListActive(ctx); err == nil {
				t.Error("ListActive succeeded; want the I/O error")
			}
			if err := s.Save(ctx, boundKey(t)); err == nil {
				t.Error("Save succeeded; want the I/O error, with nothing replaced")
			}
			if err := s.CreateIfAbsent(ctx, boundKey(t)); err == nil && name == "current.pem is a symlink loop" {
				t.Error("CreateIfAbsent succeeded over an unreadable current.pem; want the stat error")
			}
			if prev, err := s.LoadPrevious(ctx); err != nil || prev == nil || prev.KeyID != k1.KeyID {
				t.Errorf("LoadPrevious = %v, %v; want %s untouched", prev, err, k1.KeyID)
			}
		})
	}
}

// Keys in a directory the server cannot write (mounted read-only, say) are
// served as before: reads work, and a write fails with an error instead of
// half-writing.
func TestStore_ReadOnlyKeyDirectory_ServesKeys(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes regardless of mode")
	}
	for _, withLockFile := range []bool{true, false} {
		name := "lock file present"
		if !withLockFile {
			name = "no lock file"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			s := newStore(t, dir)
			k := boundKey(t)
			if err := s.CreateIfAbsent(ctx, k); err != nil {
				t.Fatalf("seed: %v", err)
			}
			if !withLockFile {
				if err := os.Remove(filepath.Join(dir, ".lock")); err != nil {
					t.Fatalf("remove lock: %v", err)
				}
			}
			if err := os.Chmod(dir, 0o500); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

			ro, err := New(dir, observability.NewNoop())
			if err != nil {
				t.Fatalf("New on a read-only key directory: %v", err)
			}
			cur, err := ro.LoadCurrent(ctx)
			if err != nil || cur == nil || cur.KeyID != k.KeyID {
				t.Fatalf("LoadCurrent = %v, %v; want %s", cur, err, k.KeyID)
			}
			if active, err := ro.ListActive(ctx); err != nil || len(active) != 1 {
				t.Fatalf("ListActive = %v, %v; want the one key", active, err)
			}
			if err := ro.Save(ctx, boundKey(t)); err == nil {
				t.Fatal("Save into a read-only key directory succeeded; want an error")
			}
			if cur, err := ro.LoadCurrent(ctx); err != nil || cur.KeyID != k.KeyID {
				t.Fatalf("after the failed Save, LoadCurrent = %v, %v; want %s unchanged", cur, err, k.KeyID)
			}
		})
	}
}
