package scope

import (
	"sort"
	"strings"
)

// Set is an unordered set of scope strings.
type Set map[string]struct{}

// Parse splits a space-separated scope string into a Set.
// Empty input returns an empty (non-nil) set.
func Parse(s string) Set {
	ss := make(Set)
	for _, part := range strings.Fields(s) {
		ss[part] = struct{}{}
	}
	return ss
}

// New creates a Set from individual scope strings.
func New(scopes ...string) Set {
	ss := make(Set, len(scopes))
	for _, s := range scopes {
		if s != "" {
			ss[s] = struct{}{}
		}
	}
	return ss
}

// String returns the scopes as a sorted space-separated string.
// Sorting ensures deterministic output.
func (ss Set) String() string {
	if len(ss) == 0 {
		return ""
	}
	sorted := make([]string, 0, len(ss))
	for s := range ss {
		sorted = append(sorted, s)
	}
	sort.Strings(sorted)
	return strings.Join(sorted, " ")
}

// Contains reports whether scope is in the set.
func (ss Set) Contains(scope string) bool {
	_, ok := ss[scope]
	return ok
}

// IsEmpty reports whether the set has no scopes.
func (ss Set) IsEmpty() bool {
	return len(ss) == 0
}

// Len returns the number of scopes in the set.
func (ss Set) Len() int {
	return len(ss)
}

// IsSubset reports whether every scope in ss is also in other.
func (ss Set) IsSubset(other Set) bool {
	for s := range ss {
		if !other.Contains(s) {
			return false
		}
	}
	return true
}

// Intersect returns a new Set containing only scopes present in both sets.
func (ss Set) Intersect(other Set) Set {
	result := make(Set)
	// iterate over the smaller set for efficiency
	a, b := ss, other
	if len(a) > len(b) {
		a, b = b, a
	}
	for s := range a {
		if b.Contains(s) {
			result[s] = struct{}{}
		}
	}
	return result
}

// Union returns a new Set containing all scopes from both sets.
func (ss Set) Union(other Set) Set {
	result := make(Set, len(ss)+len(other))
	for s := range ss {
		result[s] = struct{}{}
	}
	for s := range other {
		result[s] = struct{}{}
	}
	return result
}

// Equal reports whether two ScopeSets contain the same scopes.
func (ss Set) Equal(other Set) bool {
	if len(ss) != len(other) {
		return false
	}
	return ss.IsSubset(other)
}

// Slice returns the scopes as a sorted string slice.
func (ss Set) Slice() []string {
	sorted := make([]string, 0, len(ss))
	for s := range ss {
		sorted = append(sorted, s)
	}
	sort.Strings(sorted)
	return sorted
}
