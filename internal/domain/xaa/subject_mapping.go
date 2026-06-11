package xaa

import "time"

// SubjectMapping maps an external IdP subject to a local user identity.
type SubjectMapping struct {
	ID          string
	IDPID       string // Which trusted IdP
	IDPSubject  string // Subject at IdP (e.g., "user@acme.com")
	LocalUserID string // Our local user ID (empty = auto-provision in auto_map mode)
	CreatedAt   time.Time
}
