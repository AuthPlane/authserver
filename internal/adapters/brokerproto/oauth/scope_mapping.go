package oauth

import (
	"github.com/authplane/authserver/internal/domain/resource"
)

// mapScopes translates a list of fine scope names (as advertised in
// resource.Scopes[].Name) into the upstream wire-format scope strings the
// upstream OAuth provider expects. The mapping rule is:
//
//   - if r.Scopes[i].Name == fine and r.Scopes[i].Upstream != "", emit Upstream
//   - if r.Scopes[i].Name == fine and r.Scopes[i].Upstream == "", emit fine
//     (passthrough — defensive; Mint resources never reach this adapter,
//     and a Broker scope without an Upstream override is treated as already
//     wire-format)
//   - if fine is not registered on r at all, drop it silently
//     (unknown scopes are filtered upstream by BrokerIssuer's catalog check
//     in ; this is defense-in-depth)
//
// Order of the input is preserved in the output. Duplicates in the input are
// preserved verbatim — de-duplication is not the adapter's concern.
//
// Per the resource-unification design (scope layering). this
// is the *fine→upstream wire* mapping; the upstream→fine direction is not
// the adapter's job (the AS stores upstream-format scopes_granted as-is).
func mapScopes(r *resource.Resource, requested []string) []string {
	if r == nil || len(requested) == 0 {
		return nil
	}
	index := make(map[string]string, len(r.Scopes))
	for _, s := range r.Scopes {
		index[s.Name] = s.Upstream
	}
	out := make([]string, 0, len(requested))
	for _, fine := range requested {
		upstream, ok := index[fine]
		if !ok {
			continue
		}
		if upstream == "" {
			out = append(out, fine)
			continue
		}
		out = append(out, upstream)
	}
	return out
}
