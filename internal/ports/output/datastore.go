package output

import "context"

// DataStore provides unified access to all storage backends and lifecycle management.
// Each adapter (sqlite, postgres) implements this interface.
type DataStore interface {
	Client() ClientStore
	User() UserStore
	Session() SessionStore
	Token() TokenStore
	Audit() AuditStore
	Revocation() RevocationStore
	MachineToken() MachineTokenStore
	DPoPNonce() DPoPNonceStore
	RuntimeSettings() RuntimeSettingsStore
	IDP() IDPStore
	AssertionJTI() AssertionJTIStore
	XAAPolicy() XAAPolicyStore
	SubjectMapping() SubjectMappingStore
	Transaction() TransactionManager
	Resource() ResourceStore
	BrokerProvider() BrokerProviderStore
	ConsentGrant() ConsentGrantStore
	BrokerGrant() BrokerGrantStore
	Issuance() IssuanceStore
	ConnectPendingState() ConnectPendingStateStore
	FrontingLink() FrontingLinkStore

	// Migrate runs pending database migrations.
	Migrate(ctx context.Context) error

	// Ping verifies the database connection is alive.
	Ping(ctx context.Context) error

	// Close releases the database connection.
	Close() error
}
