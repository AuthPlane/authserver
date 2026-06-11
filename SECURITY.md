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

### Out of Scope

- Denial of service (unless < 10 requests trigger it)
- Social engineering
- Issues in dependencies (report upstream, notify us)
- Self-hosted misconfiguration (document it instead)

## Security Design

Authplane's security design is documented at:

- [Threat Model](docs/security/threat-model.md)
- [Token Design](docs/security/token-design.md)
- [Key Management](docs/security/key-management.md)

## Contact

For non-vulnerability security questions, open a [discussion](https://github.com/authplane/authserver/discussions).
