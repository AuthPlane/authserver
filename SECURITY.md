# Security Policy

## Supported Versions

Only the latest minor release receives security patches. Authplane is in early development (0.x); pin to a specific version and watch the release feed for security advisories.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, use [GitHub Private Vulnerability Reporting](https://github.com/authplane/authserver/security/advisories/new) to submit your report. This ensures:

- Your report is confidential and only visible to maintainers
- We can coordinate a fix before public disclosure
- You receive credit for responsible disclosure

### What to Include

- Description of the vulnerability
- Steps to reproduce (or proof of concept)
- Affected versions
- Impact assessment (what an attacker could do)

### Response Timeline

- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 5 business days
- **Fix timeline:** depends on severity (critical: < 7 days, high: < 14 days)

### What We Consider In-Scope

- Authentication bypasses (OAuth flow, PKCE, client authentication)
- Token forgery, replay, or privilege escalation
- Cryptographic weaknesses (signing, encryption, key management)
- Injection vulnerabilities (SQL, template, header)
- Sensitive data exposure (tokens, secrets, keys in logs or responses)
- DPoP proof bypass or binding issues
- Token exchange authorization bypass
- Cross-site attacks (CSRF, XSS on consent/login pages)
- Application-logic denial of service (asymmetric cost: a single actor, authenticated or not, can deny service to a user, a client, or the whole instance)

### Out of Scope

- Volumetric and network-layer denial of service (packet floods, amplification, exhaustion by sheer traffic volume)
- Load- and stress-testing artefacts (throughput ceilings, saturation under synthetic traffic)
- Social engineering
- Issues in dependencies (report upstream, notify us)
- Self-hosted misconfiguration (document it instead)

## Security Design

Authplane's security design, and the operator procedures that implement it, are documented at:

- [Threat Model](docs/concepts/threat-model.md)
- [Tokens and Claims](docs/concepts/tokens-and-claims.md)
- [Key Rotation](docs/guides/operate/key-rotation.md) — operator runbook
- [Verifying releases](docs/guides/deploy/verifying-releases.md) — cosign signature and SBOM verification for release artifacts and container images

## Contact

For non-vulnerability security questions, open a [discussion](https://github.com/authplane/authserver/discussions).
