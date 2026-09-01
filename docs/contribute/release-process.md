*Context: this is part of [Contribute](README.md). Start with the primer if you haven't.*

# Release process

Releases produce three artefacts in lockstep:

1. Tagged GitHub Release with platform binaries.
2. Multi-arch Docker images at `authplane/authserver:<tag>`.
3. A Helm chart bump under [`charts/authplane/`](../../charts/authplane/).

The CI step is driven by [goreleaser](../../.goreleaser.yml) and
triggered by a `v*` git tag. Everything else is manual prep.

## Branching

- `develop` — integration branch; all PRs land here.
- `main` — release branch; fast-forwarded from `develop` at release time.
- Feature branches: `<author>/<short-name>` off `develop`.

No long-lived release branches; the tag is the release.

## 1. Pick a version

Use semver. authserver is pre-1.0 today (see
[`charts/authplane/Chart.yaml`](../../charts/authplane/Chart.yaml)
`appVersion`) so the convention is:

- Breaking wire / DTO / config change → bump minor.
- Bug fix / additive change → bump patch.

Releases up to 1.0 do not promise wire stability across minor bumps.
After 1.0, only major bumps may break wire compat.

## 2. Update `CHANGELOG.md`

Move entries out of `## [Unreleased]` into a new `## [vX.Y.Z] — YYYY-MM-DD`
section. The format follows [Keep a Changelog](https://keepachangelog.com/);
keep entries operator-facing — wire changes, config additions,
behavioural shifts — not internal refactors.

Categories used: `Added`, `Changed`, `Fixed`, `Deprecated`, `Removed`,
`Security`. The existing entries under
[`CHANGELOG.md`](../../CHANGELOG.md) are the style reference.

goreleaser also generates a release-notes block from commit messages
(see the `changelog` section of
[`.goreleaser.yml`](../../.goreleaser.yml)); the hand-written changelog
is the authoritative one — the auto-generated one is supplemental.

## 3. Bump the Helm chart

In [`charts/authplane/Chart.yaml`](../../charts/authplane/Chart.yaml):

- `appVersion` — the authserver image tag the chart pulls (`"X.Y.Z"`).
  Bumps every authserver release. The `artifacthub.io/images` annotation
  hardcodes the same tag for ArtifactHub's scanner (Helm can't template it
  from `appVersion`) — bump both in lockstep, or the chart page drifts.
- `version` — the chart's own version (`X.Y.Z`). Bump patch for image-only
  changes; bump minor when chart values / templates change.

The two version numbers move independently. A chart-only change (new
values key, template fix) ships as a chart-version bump without an
authserver release.

## 4. Run the gate

```bash
make ci-local
make test-integration
make test-integration-postgres
make test-e2e
make docs-check
```

If anything is red, fix it before tagging — there's no clean way to
unship a tag once it has triggered goreleaser.

## 5. Land on `main` and tag

```bash
git checkout main
git pull origin main
git merge --ff-only develop
git push origin main

git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

The `v` prefix is required by goreleaser.

## 6. What CI does next

The release workflow consumes the tag and runs goreleaser. Per
[`.goreleaser.yml`](../../.goreleaser.yml):

- Pre-flight: `go mod tidy` + `make check-imports` (the `before` hooks).
- Cross-compiles `authserver` for `linux/{amd64,arm64}` and
  `darwin/{amd64,arm64}` from
  [`cmd/authserver`](../../cmd/authserver/) — `CGO_ENABLED=0`, ldflags
  injecting `version`, `commit`, `date`.
- Packages tarballs under `authserver_<version>_<os>_<arch>.tar.gz`
  bundled with `LICENSE`, `README.md`, `CHANGELOG.md`.
- Builds two single-arch Docker images via
  [`build/Dockerfile.goreleaser`](../../build/Dockerfile.goreleaser) and
  pushes them to `authplane/authserver:<version>-{amd64,arm64}`.
- Stitches the manifest at `authplane/authserver:<version>`
  (and `:latest` on stable tags).
- Drafts the GitHub Release with the generated changelog + checksum file.

## 7. Post-release: bump SDK pins

Sibling SDK repos (`../go-sdk`, `../ts-sdk`, `../python-sdk`) and
in-repo examples under
[`examples/{go,typescript,python}/`](../../examples/) pin specific SDK
versions. After a release that changes the wire shape:

- Cut matching SDK releases from the sibling repos.
- Bump the SDK version pin in every example's `go.mod` / `package.json`
  / `pyproject.toml` to match.
- Run `make docs-smoke` to confirm every example still passes against
  the new binary + new SDK pin.

## 8. Sanity-check the artefacts

```bash
# Helm chart pulls the right image:
helm show values charts/authplane | grep -E '^\s*tag:'
docker pull authplane/authserver:X.Y.Z
docker run --rm authplane/authserver:X.Y.Z version

# Binary tarball boots:
curl -sL https://github.com/authplane/authserver/releases/download/vX.Y.Z/authserver_X.Y.Z_linux_amd64.tar.gz | tar -xz
./authserver version
```

If any of those fail, open a hot-fix PR and cut `vX.Y.(Z+1)` —
do not retag.

## Hot fixes

For a critical fix off an already-released tag:

1. Branch from the release tag: `git checkout -b hotfix/<issue> vX.Y.Z`.
2. Cherry-pick or write the fix; add a `Fixed` entry under a new
   `## [vX.Y.(Z+1)] — YYYY-MM-DD` heading in `CHANGELOG.md`.
3. Bump `charts/authplane/Chart.yaml` (both `appVersion` and `version`
   patch).
4. Run the gate.
5. Merge into `main`, tag `vX.Y.(Z+1)`, push.
6. Back-merge into `develop`.
