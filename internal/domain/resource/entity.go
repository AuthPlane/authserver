// Package resource contains domain types for the unified Resource registry
// and its companion shapes.
package resource

// Scope is a permission advertised by a resource. Name is the scope string
// (e.g. "tools/query_database"); Description is the human-readable label
// shown on consent screens and in Protected Resource Metadata. Upstream is
// the wire-format scope at the upstream provider used only by Broker-backed
// resources; it is empty for Mint-backed resources.
type Scope struct {
	Name        string
	Description string
	Upstream    string
}
