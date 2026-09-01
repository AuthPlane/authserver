// Package static hosts the default, configuration-driven adapter
// implementations for trivial output ports — the ones whose impl is a
// constant value captured from configuration at boot.
//
//   - static.CORSConfigProvider    — implements output.CORSConfigProvider
//   - static.IssuerProvider        — implements output.IssuerProvider
//   - static.LoginDisplayProvider  — implements output.LoginDisplayProvider
//   - static.StateCodec            — implements output.StateCodec
//   - static.URLBuilder            — implements output.URLBuilder
//
// Adapters here perform NO I/O and have NO dependencies beyond stdlib
// and internal/ports/output. The expectation is that each adapter is
// only a few lines of code, returning a stored value verbatim on every
// call.
//
// Adapters that touch real infrastructure (Postgres, Redis, KMS, …) do
// not belong in this package — they live in internal/adapters/<infra>/
// alongside the other tech-specific adapters.
package static
