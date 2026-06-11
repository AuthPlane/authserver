package brokerproto

import (
	"fmt"
	"regexp"
)

// validEnvVarName matches environment variable names that the brokerproto
// adapters are allowed to look up. The allowlist prevents an operator-supplied
// config row from naming an arbitrary process env var (PATH, AWS_*, …) and
// having the adapter return its value as a "client secret".
var validEnvVarName = regexp.MustCompile(`^(CONNECTOR_|AUTHPLANE_VAULT_)[A-Z][A-Z0-9_]*$`)

// ValidEnvVarName reports whether name matches the allowed pattern
// (CONNECTOR_* or AUTHPLANE_VAULT_* prefix, uppercase + digits + underscores).
func ValidEnvVarName(name string) bool {
	return validEnvVarName.MatchString(name)
}

// ReservedAuthParams lists OAuth authorize parameters that an upstream-config
// extra_auth_params map must not override. Enforced at validation time and as
// defense in depth in the brokerproto/oauth adapter.
var ReservedAuthParams = map[string]struct{}{
	"client_id":             {},
	"client_secret":         {},
	"response_type":         {},
	"state":                 {},
	"code_challenge":        {},
	"code_challenge_method": {},
	"redirect_uri":          {},
	"scope":                 {},
}

// Bounds on extra_auth_params to keep authorize URLs and the JSON column
// from bloating if an operator pastes arbitrary data. Generous for legitimate
// OAuth params (access_type=offline, hd=example.com, login_hint=…).
const (
	MaxExtraAuthParams        = 20
	MaxExtraAuthParamKeyLen   = 256
	MaxExtraAuthParamValueLen = 256
)

// ValidateExtraAuthParams returns an error if params contains any reserved
// OAuth key, an empty key, exceeds the per-entry size caps, or declares more
// than MaxExtraAuthParams entries.
func ValidateExtraAuthParams(params map[string]string) error {
	if len(params) > MaxExtraAuthParams {
		return fmt.Errorf("extra_auth_params: too many entries (max %d)", MaxExtraAuthParams)
	}
	for k, v := range params {
		if k == "" {
			return fmt.Errorf("extra_auth_params: empty key not allowed")
		}
		if len(k) > MaxExtraAuthParamKeyLen {
			return fmt.Errorf("extra_auth_params: key too long (max %d chars)", MaxExtraAuthParamKeyLen)
		}
		if len(v) > MaxExtraAuthParamValueLen {
			return fmt.Errorf("extra_auth_params: value for %q too long (max %d chars)", k, MaxExtraAuthParamValueLen)
		}
		if _, reserved := ReservedAuthParams[k]; reserved {
			return fmt.Errorf("extra_auth_params: %q is a reserved OAuth parameter", k)
		}
	}
	return nil
}
