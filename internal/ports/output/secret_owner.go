package output

// Owner identifies the entity that owns a config secret. The (Kind, ID) pair
// composes the ownerContext under which the secret's ciphertext is encrypted
// and decrypted, keeping each entity's secret cryptographically isolated.
type Owner struct {
	Kind OwnerKind
	ID   string
}

// OwnerKind types the ownerContext prefix and prevents typos.
type OwnerKind string

const (
	OwnerKindBrokerProvider OwnerKind = "broker-provider"
	OwnerKindOIDC           OwnerKind = "oidc"
)
