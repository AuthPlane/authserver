# Verifying releases

Every release is signed with [cosign](https://docs.sigstore.dev/) in keyless
mode and ships a [syft](https://github.com/anchore/syft) SBOM per archive.
Keyless means there is no public key to distribute or rotate: the signature is
bound to the GitHub Actions workflow that produced it, and the proof is
recorded in the public [Rekor](https://docs.sigstore.dev/logging/overview/)
transparency log.

Verifying is therefore not "check a checksum" — it is "confirm these bytes were
built by *this* workflow, from *this* tag, in *this* repository". A checksum
alone proves only that a download was not corrupted; it says nothing about who
produced it.

You need [cosign installed](https://docs.sigstore.dev/system_config/installation/).

Throughout, replace `0.1.2` with the release you are verifying. Archives use
the version without a leading `v`; the git tag has one.

## Release artifacts

- `authserver_<version>_<os>_<arch>.tar.gz` — the binary archive
- `authserver_<version>_<os>_<arch>.tar.gz.sbom.json` — its SBOM
- `checksums.txt` — SHA-256 of every archive
- `checksums.txt.sig` / `checksums.txt.pem` — the cosign signature and its
  short-lived certificate

The signature covers `checksums.txt`, not each archive individually. That one
signature transitively covers every artifact, so verification is two steps:
authenticate `checksums.txt`, then check your download against it. Doing only
the second step verifies nothing about origin.

## Verify a binary release

```bash
VERSION=0.1.2
BASE="https://github.com/authplane/authserver/releases/download/v${VERSION}"
curl -fsSLO "${BASE}/authserver_${VERSION}_linux_amd64.tar.gz"
curl -fsSLO "${BASE}/checksums.txt"
curl -fsSLO "${BASE}/checksums.txt.sig"
curl -fsSLO "${BASE}/checksums.txt.pem"
```

Step 1 — authenticate `checksums.txt`:

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity "https://github.com/authplane/authserver/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
```

Expect `Verified OK`.

Step 2 — check the archive against the now-trusted checksums:

```bash
sha256sum --ignore-missing -c checksums.txt
```

Expect `authserver_0.1.2_linux_amd64.tar.gz: OK`. On macOS, `shasum -a 256 -c`.

Both steps must pass. Step 1 without step 2 proves a `checksums.txt` you may
not have compared anything against; step 2 without step 1 proves only internal
consistency between two files an attacker could have replaced together.

## Verify the container image

```bash
cosign verify \
  --certificate-identity "https://github.com/authplane/authserver/.github/workflows/release.yml@refs/tags/v0.1.2" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  authplane/authserver:0.1.2
```

Pin by digest in production so the tag cannot be repointed after you verify it:

```bash
docker pull authplane/authserver:0.1.2
docker inspect --format='{{index .RepoDigests 0}}' authplane/authserver:0.1.2
```

## Inspect the SBOM

Each archive has a CycloneDX SBOM listing its dependencies — useful for feeding
a scanner or answering "does this release contain X?".

```bash
curl -fsSLO "https://github.com/authplane/authserver/releases/download/v0.1.2/authserver_0.1.2_linux_amd64.tar.gz.sbom.json"
grep -o '"name":"[^"]*"' authserver_0.1.2_linux_amd64.tar.gz.sbom.json | sort -u | head
```

The SBOM is covered by `checksums.txt`, so verify that first if you intend to
rely on it.

## What the identity means

`--certificate-identity` is the exact workflow and tag that signed the release.
It is what makes the check meaningful: a signature made by any other workflow,
repository, or tag fails verification even though it is a perfectly valid
Sigstore signature.

Pin it to the exact tag as shown. Loosening it to
`--certificate-identity-regexp` with a broad pattern will accept signatures
from other tags — and, if the pattern is loose enough, other repositories.

## If verification fails

Do not install the artifact. A failure is one of:

- **Wrong `--certificate-identity`** — the version in the identity string must
  match the tag you downloaded from. This is the common cause.
- **Re-downloaded one file but not the others** — `checksums.txt`, its `.sig`
  and `.pem` are a set and must come from the same release.
- **A genuine mismatch** — report it via [SECURITY.md](../../../SECURITY.md).
  Do not open a public issue.
