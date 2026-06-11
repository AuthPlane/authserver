package config

// EnabledGrantTypes returns the list of OAuth grant types the running AS
// is configured to honor. authorization_code and refresh_token are always
// available; the optional grants (client_credentials, token-exchange,
// jwt-bearer) appear only when their per-feature config flag is set.
//
// The returned slice is consumed by client.ValidateCreateParams
// to reject admin/DCR client registrations that ask for a grant the
// /oauth/token endpoint can't actually serve.
func EnabledGrantTypes(cfg *Config) []string {
	grants := []string{"authorization_code", "refresh_token"}
	if cfg.ClientCredentials.Enabled {
		grants = append(grants, "client_credentials")
	}
	if cfg.TokenExchange.Enabled {
		grants = append(grants, "urn:ietf:params:oauth:grant-type:token-exchange")
	}
	if cfg.XAA.Enabled {
		grants = append(grants, "urn:ietf:params:oauth:grant-type:jwt-bearer")
	}
	return grants
}
