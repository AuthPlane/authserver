package crypto

import "golang.org/x/crypto/bcrypt"

// DefaultBcryptCost is the bcrypt cost factor for hashing client secrets.
const DefaultBcryptCost = 12

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
