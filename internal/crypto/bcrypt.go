package crypto

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// DefaultBcryptCost is the bcrypt cost factor for hashing client secrets.
//
// Raising it is not a drop-in change. Stored hashes carry the cost they were
// written with, so a bump applies only to new ones, and the login path derives
// against a dummy pinned to this constant whenever there is no stored hash to
// use. Mixed costs are a timing oracle in their own right — a cost-4 hash
// compares in ~830us against ~206ms for cost 12 — so bumping this without
// rehashing the existing rows would separate old accounts from new ones and
// from unknown addresses, which is the defect the dummy exists to close.
// Rehash on successful login, or migrate, before changing it.
//
// The same holds for hashes arriving from elsewhere. bcrypt accepts the $2b$
// and $2y$ minor versions and any cost, so users imported from another product
// keep whatever cost that product wrote: a $2b$10$ row denies in ~52ms against
// the dummy's ~206ms, and the enumeration oracle returns for exactly the
// imported population. An importer should rehash at DefaultBcryptCost rather
// than carry the foreign hash across.
const DefaultBcryptCost = 12

// dummyBcryptHash is a real bcrypt hash at DefaultBcryptCost whose plaintext was
// discarded at generation time and is recorded nowhere. It exists so an
// authentication path that has no stored hash to check — no such account, a
// federated account, a disabled one — can still spend the same key-derivation
// time as a path that does. Nothing may authenticate against it: every caller
// throws the comparison result away.
//
// Regenerate with bcrypt.GenerateFromPassword over 32 bytes of crypto/rand at
// DefaultBcryptCost. The value is public by construction — publishing it costs
// nothing, because knowing the hash does not shorten the derivation an attacker
// would have to observe.
const dummyBcryptHash = "$2a$12$9hJ4zxEv2lF/t.5TMcCUKeezsZZRUypa3rEeeU7uAh7CzEf8klN5u"

// A dummy hash that does not parse, or parses at the wrong cost, is worse than
// none: bcrypt.CompareHashAndPassword rejects a malformed hash before deriving
// anything, so DummyBcryptHash would return in microseconds and silently
// reinstate the timing oracle it exists to close. Check the constant once at
// process start rather than trusting it to stay correct through future edits.
func init() {
	cost, err := bcrypt.Cost([]byte(dummyBcryptHash))
	if err != nil {
		panic(fmt.Sprintf("crypto: dummy bcrypt hash does not parse: %v", err))
	}
	if cost != DefaultBcryptCost {
		panic(fmt.Sprintf("crypto: dummy bcrypt hash cost is %d, want %d", cost, DefaultBcryptCost))
	}
}

// DummyBcryptHash returns a hash to compare against when the real one is absent
// or unusable, so that every branch of an authentication decision costs the
// same. Pass it to CompareBcrypt exactly as you would a stored hash; the
// comparison never succeeds, and the caller is expected to have already decided
// to deny.
func DummyBcryptHash() string {
	return dummyBcryptHash
}

// ErrUnusableHash reports that a stored hash never reached key derivation —
// empty, truncated, an unknown version, a salt outside bcrypt's alphabet. It is
// a broken row rather than a wrong password, and worth telling apart in the
// trail even though both deny.
var ErrUnusableHash = errors.New("crypto: stored bcrypt hash is not derivable")

// CompareBcryptUniform compares plaintext against hash and guarantees that
// exactly one full key derivation happens, whatever shape hash is in. Use it
// wherever the time a comparison takes must not depend on what was stored.
//
// CompareBcrypt cannot promise that: it rejects a malformed hash before
// deriving anything and returns in well under a microsecond, which on an
// authentication path is a timing oracle for whichever accounts happen to hold
// a broken hash. Checking the hash beforehand does not close it either —
// bcrypt.Cost parses the version and cost but never decodes the salt, so a
// hash with a legal $2a$12$ prefix and an illegal salt passes every structural
// check available and still bails in ~600ns. So this derives first and repairs
// after: any outcome other than a match or a genuine mismatch means nothing was
// derived, and the cost gets paid against the dummy instead.
//
// The dummy comparison's result is discarded here and cannot reach the caller,
// which is what keeps the dummy from ever admitting anybody: a caller holding
// its plaintext gets ErrUnusableHash exactly like anyone else.
func CompareBcryptUniform(hash, plaintext string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
	if err == nil || errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return err
	}
	_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(plaintext))
	return fmt.Errorf("%w: %v", ErrUnusableHash, err)
}

// HashBcrypt returns the bcrypt hash of the given plaintext.
func HashBcrypt(plaintext string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), DefaultBcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CompareBcrypt compares a bcrypt hash with a plaintext string.
// Returns nil on match, error otherwise.
func CompareBcrypt(hash, plaintext string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
}
