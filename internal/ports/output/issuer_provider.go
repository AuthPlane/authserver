package output

import "context"

// IssuerProvider returns the OAuth Authorization Server issuer URL
// applicable to the request being served. Implementations may resolve
// the value from configuration, from ctx, or from a backing store, and
// MAY return an error when resolution fails. Callers MUST treat an
// empty return value as a programming error.
type IssuerProvider interface {
	Issuer(ctx context.Context) (string, error)
}
