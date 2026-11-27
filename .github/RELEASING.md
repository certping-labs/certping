# Releasing

## Versions

One version for the whole repository; all four apps are released together.
Semantic Versioning with a leading `v`:

| Version | Meaning |
| --- | --- |
| `v0.1.0-alpha.1`, `-alpha.2`, ... | Early previews. Anything can change. |
| `v0.0.1-beta`, `v0.1.0-beta.1`, `-rc.1` | Public beta or release candidate, being tested. |
| `v0.1.0` | First usable, documented release. |
| `v0.x.y` patch | Compatible fixes. |
| `v0.(x+1).0` minor | New features. During 0.x a minor may break things; release notes must say so. |
| `v1.0.0` | Only once the API and configuration contract is declared stable. |

The first public release is `v0.0.1-beta`, a public beta. Published tags are
never moved, deleted or reused. During 0.x no release is described as
production ready; that waits for `v1.0.0` and a declared stable API and
configuration contract.

## Cutting a release

Releases are manual. Merging to `main` never releases anything, and nothing in
the workflow publishes by itself: the result is a draft that a maintainer
reviews and publishes by hand.

1. Make sure `main` is green: the `CI` and `Security` workflows must have
   completed successfully for the exact commit you are releasing. The Release
   workflow checks this and refuses otherwise.
2. Open Actions, select the Release workflow, then Run workflow on branch
   `main`, and enter the version. Leave `publish_images` off for a dry run, or
   turn it on to push images. For a stable version (no `-alpha`, `-beta` or
   `-rc`), also tick `stable_release_checklist_done` after completing the
   checklist below.
3. The workflow (`.github/workflows/release.yml`):
   - checks the version format, that the tag and release do not exist, that
     the commit is on `main`, and that the checks `ci-required`,
     `Secret scan (gitleaks)` and `Dependency and config scan (trivy)` passed
     for that commit;
   - records whether the trivy scan was blocking or report-only for the
     commit (from `exit-code` in `.github/trivy.yaml`);
   - asks for approval: the `approve` job waits in the `release` environment
     on every run, and for a stable version the `approve-stable` job waits in
     `release-stable` as well. Nothing is built before approval. The full CI
     runs on that exact commit again while the approval waits;
   - builds each of the four application images on a native runner per
     platform (`ubuntu-24.04` for `linux/amd64`, `ubuntu-24.04-arm` for
     `linux/arm64`), with OCI labels (source, revision, version). When
     publishing, each platform image is pushed by digest and the two are
     joined into one tagged multi-platform manifest,
     `ghcr.io/certping-labs/certping-<app>:<version>`;
   - when publishing, scans each platform image by digest with trivy before
     it is tagged (`.github/scripts/image-scan.sh`): operating system packages
     and application dependencies, fixable HIGH and CRITICAL findings, with
     the settings, exceptions and blocking or report-only mode of the Security
     workflow (`.github/trivy.yaml`, `.github/.trivyignore.yaml`). In blocking
     mode an open finding stops the release before anything is tagged;
   - when publishing, collects the corresponding source of each image and
     pushes it next to the image as `ghcr.io/certping-labs/<image>-source:<version>`
     before the image is tagged (see "Corresponding source" below);
   - when publishing, builds the all-in-one image `ghcr.io/certping-labs/certping:<version>`
     from those four images by digest (its arm64 half runs under QEMU), and
     scans it and publishes its source the same way before tagging it;
   - packages the self-hosting kits: `certping-compose-<version>.zip` (the
     Compose kit with the images pinned to the release, by digest when
     published) and the two Helm charts as `.tgz` with LICENSE and NOTICE;
   - when publishing, pushes those chart packages to
     `oci://ghcr.io/certping-labs/charts`, and, once Docker Hub is set up,
     copies all five images unchanged (same digests) to
     `docker.io/<namespace>/certping` and `docker.io/<namespace>/certping-<app>`;
   - writes a CycloneDX SBOM per image, the image scan reports
     (`trivy-<image>-linux-<arch>.json`), a source index per image
     (`source-<image>.txt`), a `release-metadata.json` and a `SHA256SUMS`
     file covering every attached file;
   - signs pushed images with cosign (keyless), attaches build provenance and
     SBOM attestations to them, signs `SHA256SUMS` with cosign, and attests
     every attached file (public repository only);
   - creates a draft release with generated notes, contributor credits, the
     image digests, the source locations and a "Security scan status" section
     that says which scan mode applied and what the image scan found. No tag
     exists yet.
4. Edit the draft: fill in upgrade notes and breaking changes, check the
   generated notes and credits, and keep the scan status section as written.
   A dry-run draft (images not pushed) says so; delete it instead.
5. Publish the draft. Publishing creates the tag on the release commit. A
   second maintainer looks at the draft before it is published.

## GitHub settings to configure once

The workflows assume these repository settings. Set them before the first
release, when the repository is made public. While the repository is private
on the GitHub Free plan, rulesets and environments are not available, so the
pull request flow below is followed by agreement rather than enforced.

| Setting | Where | Value |
| --- | --- | --- |
| Environments | Settings, Environments | `release` and `release-stable`, each with required reviewers (the `@certping-labs/certping` team) and **Deployment branches and tags** limited to `main`. Until they exist with reviewers, the approval jobs pass without asking. |
| Default token permissions | Settings, Actions, General, Workflow permissions | **Read repository contents and packages permissions**. Each job asks for what it needs. Leave "Allow GitHub Actions to create and approve pull requests" off. |
| Branch ruleset for `main` | Settings, Rules, Rulesets | Require a pull request with 1 approval and review from code owners (`@certping-labs/certping`), dismiss approvals on new pushes, require conversations to be resolved, allow squash merges only, block force pushes and deletion, and require the status checks `ci-required` (it includes the DCO sign-off check), `Dependency review`, `Secret scan (gitleaks)` and `Dependency and config scan (trivy)`. |
| GHCR packages | Your profile or organization, Packages | After the first published release: set `certping`, `certping-server`, `certping-web`, `certping-agent`, `certping-notifier`, the source packages `certping-source`, `certping-server-source`, `certping-web-source`, `certping-agent-source`, `certping-notifier-source`, and `charts/certping` and `charts/certping-agent` to public, and connect each to the `certping-labs/certping` repository. The source packages must be public before the release is published: the notices in the images point to them. |
| Code scanning | Settings, Security (Code security) | On. The weekly Image scan workflow uploads its results there. |
| Docker Hub | Settings, Secrets and variables, Actions | Variable `DOCKERHUB_NAMESPACE` (the Docker Hub organization), secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` (an access token with read and write scope). Create the repositories `certping`, `certping-server`, `certping-web`, `certping-agent` and `certping-notifier` in that organization first. Without the variable, releases go to GHCR only. |
| Discussions | Settings, General, Features | On. The README, `SUPPORT.md` and the issue template link to it. |
| Private vulnerability reporting | Settings, Security (Advisories) | On. `SECURITY.md` names it as a reporting channel. |
| Dependency graph and Dependabot alerts | Settings, Security (Code security) | On. The Dependency review workflow needs the dependency graph. |

Native arm64 runners, keyless signing and artifact attestations are free only
on public repositories, so run the first real release after the repository is
public.

## Stable-release checklist (`v0.1.0` and later without a suffix)

Done before ticking `stable_release_checklist_done`:

- A pre-release of the same code (`-rc.n`) was published and installed from
  the published images with the Compose or Helm kit, and `deploy/compose/smoke-test.sh`
  passed against it.
- The trivy scan is in blocking mode, or every open finding has an entry in
  `.github/.trivyignore.yaml` with a statement.
- Upgrade notes cover every database migration and configuration change since
  the previous stable release.
- `README.md` and `docs/self-hosting.md` were re-read against the code.
- The maintainers in `MAINTAINERS.md` agree to release.

## What each artifact proves

Four different things can be verified, and they are proven by different
mechanisms. Checking one does not check the others.

| Question | Proven by | Where |
| --- | --- | --- |
| Source and tag authenticity: is this tag the commit the maintainers released? | The GitHub release is created by the Release workflow from a commit on `main`, with `--target <sha>`, and the tag is created on publish. Commit signatures are not required yet. | Release page, `release-metadata.json` (`commit`) |
| Container image authenticity: was this image pushed by this repository's release workflow? | Sigstore keyless signature on the image digest. The signing identity is the Release workflow of `certping-labs/certping`, not a person's key. | `cosign verify` |
| Build provenance: how and from what was it built? | SLSA build provenance attestation (GitHub artifact attestations) naming the workflow, the commit and the builder. | `gh attestation verify` |
| Artifact integrity: are the files I downloaded the ones the release produced? | `SHA256SUMS` lists the checksums of every attached file (SBOMs, scan reports, source indexes, Compose kit, Helm charts, metadata); the Sigstore bundle `SHA256SUMS.sigstore.json` signs that list; attestations cover every attached file. | `sha256sum -c`, `cosign verify-blob` |
| Known vulnerabilities at release time | The image scan reports, run on the pushed digests before tagging. They say what the vulnerability database knew that day, not that an image is free of vulnerabilities. | `trivy-*.json`, `release-metadata.json` (`image_scan`) |
| Source of the GPL and LGPL components | The `-source` artifact of each image, its digest in the release notes and metadata, and the SHA-256 of every file in `source-<image>.txt`. | `oras pull`, `sha256sum -c` |

Keyless signing needs a public Sigstore identity, so the workflow signs and
attests only when the repository is public. `release-metadata.json`
(`signing`) records whether a release was signed.

## Verifying a release

Replace `v0.1.0` with the version and `server` with the app.

### Checksums

```sh
gh release download v0.1.0 --repo certping-labs/certping --dir dist
cd dist && sha256sum -c SHA256SUMS
```

### Checksum signature

```sh
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/certping-labs/certping/\.github/workflows/release\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Image signature

Use the digest from the release notes or `release-metadata.json`, not the tag.

```sh
cosign verify ghcr.io/certping-labs/certping-server@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/certping-labs/certping/\.github/workflows/release\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Image provenance and SBOM attestation

```sh
gh attestation verify oci://ghcr.io/certping-labs/certping-server@sha256:<digest> \
  --repo certping-labs/certping
gh attestation verify oci://ghcr.io/certping-labs/certping-server@sha256:<digest> \
  --repo certping-labs/certping --predicate-type https://cyclonedx.org/bom
```

The first command checks the SLSA provenance (workflow, commit, builder); the
second checks that the SBOM attached to the image was produced by the same
run. `--signer-workflow certping-labs/certping/.github/workflows/release.yml`
narrows it to the release workflow.

### SBOM files

```sh
gh attestation verify dist/sbom-server.cdx.json --repo certping-labs/certping
jq '.components | length' dist/sbom-server.cdx.json
```

The SBOM lists CertPing's own software dependencies with their licenses. Feed
it to your own scanner (for example `trivy sbom dist/sbom-server.cdx.json`) to
check it against the vulnerability database of the day you install.

### Image scan reports

`trivy-<image>-linux-<arch>.json` is what the release's scan found, and lists
every package in the image. Read it with
`trivy convert --format table dist/trivy-server-linux-amd64.json`. To check an
image against today's database, scan it by digest yourself:
`trivy image ghcr.io/certping-labs/certping-server@sha256:<digest>`. The weekly
Image scan workflow does that for the latest release and reports in the
repository's Security tab.

### Corresponding source

```sh
oras pull ghcr.io/certping-labs/certping-server-source:0.1.0@sha256:<digest> -o server-source
cd server-source && grep -v '^#' SOURCES.txt | awk '{ print $1 "  " $2 }' | sha256sum -c
```

The digest is in the release notes and in `source-server.txt`, which is
covered by `SHA256SUMS`.

### Compose kit and Helm charts

`certping-compose-<version>.zip` and the chart `.tgz` files are in
`SHA256SUMS`. The kit's `docker-compose.yml` names each CertPing image as
`<version>@sha256:<digest>`; compare the digests with the release notes. The
charts pushed to `oci://ghcr.io/certping-labs/charts` are the same files.

### Deploying by digest

Pin to the verified digest rather than the tag, so what runs is what was
verified:

- All-in-one and a remote agent with `docker run`: use the image reference
  with its digest, for example `ghcr.io/certping-labs/certping@sha256:<digest>`.
- `certping-agent` chart: `--set image.tag=0.1.0@sha256:<digest>`; the chart
  renders `<repository>:<tag>`.
- Compose kit: use `certping-compose-<version>.zip` from the release assets;
  it pins all four images by digest. The kit in the repository uses the tag.
- `certping` chart: one version applies to all four images, so it cannot pin
  a digest per image yet. Check that the tag resolves to the digests in the
  release notes with
  `docker buildx imagetools inspect ghcr.io/certping-labs/certping-server:0.1.0`.

## Corresponding source

The images contain software under the GPL and the LGPL: GPL-3.0 userland
(bash, coreutils, grep, sed, tar and others), LGPL libraries, OpenJDK (GPL-2.0
with the Classpath Exception) and libvips (LGPL, used under LGPL-3.0 through
sharp). Distributing them from a registry needs their corresponding source
available from a designated place (GPL-3.0 section 6(d), LGPL-3.0 section 4).
Each release publishes it next to each image:

| Image | Source |
| --- | --- |
| `certping-<app>:<version>` | `certping-<app>-source:<version>` |
| `certping:<version>` (all-in-one) | `certping-source:<version>` |

Each is an OCI artifact in GHCR (`oras pull` restores the files) holding:

- `rpm/` (UBI images): the source RPM of every installed package, at the
  installed build, from the UBI CDN, with its Red Hat signature checked
  against the keys in the image's base image. The CDN keeps superseded builds
  by file name after the repository metadata (and so `dnf download --source`)
  drops them.
- `deb/` (all-in-one): the Ubuntu source package (`.dsc` and the files it
  lists) of every installed package, at the installed version, from the
  Ubuntu archive, or from Launchpad, which keeps every published version,
  once the archive has dropped it; each file is checked against its `.dsc`.
- `libvips/` (web and all-in-one): the source archives, patches and build
  scripts of libvips and the libraries sharp-libvips builds into it, listed
  with their SHA-256 in `licenses/components/sharp-libvips-<version>/sources.txt`,
  and `librsvg-<version>-crates.tar` with the crates.io crates of librsvg's
  `Cargo.lock`, each checked against the lockfile. The patches come from the
  copies in `patches/` beside `sources.txt`, because their hosts generate them
  on request. If a downloaded archive no longer matches its SHA-256, the
  release stops: check what changed upstream before updating the line.
- `SOURCES.txt`: every file with its SHA-256 and where it came from.

The all-in-one's Eclipse Temurin JRE (GPL-2.0 with the Classpath Exception)
is not an Ubuntu package, so `certping-source` does not hold it. The written
offer and the upstream tag in section 7 of the image's notices cover it.

Retention: never delete a `-source` package version while the image version
it belongs to is available, and keep it for at least three years after that
image was last distributed (including through Docker Hub). Deleting images
and their source is a manual step; nothing in the workflows deletes package
versions.

## Base image updates

`BASE_IMAGES` in `.github/scripts/third-party-notices.mjs` records the base
image digests that the versions in the notices (OpenJDK, Node.js, Ubuntu and
others) were read from. When a Dockerfile pins another digest, for example in
Dependabot's weekly `chore(docker)` pull request, the "Third-party notices up
to date" check fails until a maintainer updates them on that pull request:

1. Check out the pull request branch.
2. For each changed base image, read the versions from the new image, for
   example:
   ```sh
   docker run --rm --entrypoint rpm registry.access.redhat.com/ubi9/openjdk-25-runtime@sha256:<digest> \
     -q java-25-openjdk-headless
   docker run --rm --entrypoint rpm registry.access.redhat.com/ubi10/nodejs-24@sha256:<digest> -q nodejs24
   docker run --rm --entrypoint sh eclipse-temurin@sha256:<digest> -c 'java -version; . /etc/os-release; echo $VERSION'
   ```
3. Update the tag and digest in `BASE_IMAGES` and every version and source
   location read from that image in `third-party-notices.mjs`.
4. Run `.github/scripts/third-party-notices.sh`, then commit with a sign-off
   (`git commit -s`) and push.

This stays manual on purpose: the versions have to be read from the new
image, and a commit pushed by a workflow with the default token would not
start the pull request checks again, so the pull request could not merge
without a manual step anyway.

## SBOM versus CBOM

The release SBOMs list CertPing's own software dependencies. They are not a
cryptographic bill of materials. CertPing produces a CBOM of your certificate
inventory inside the product (`GET /api/v1/cbom`, CycloneDX 1.6); that is a
different document about your certificates, not about CertPing.

## Changelog and credits

Release notes are generated from merged pull requests, grouped by GitHub's default labels
`enhancement`, `bug` and `documentation` (`.github/release.yml`), and credit every author of a merged pull request. There is no separate changelog
file: the GitHub release notes are the record. Dependabot pull requests are left
out of the notes.

## Not done yet

- Commit signing is not required. Once the maintainers sign commits, the
  ruleset can require signed commits on `main`, which adds a check on source
  authenticity that today rests on GitHub access control alone.
- The trivy scan is blocking (`exit-code: 1` in `.github/trivy.yaml`), for the
  repository scan and for the image scan in the Release workflow. Any new
  fixable HIGH or CRITICAL finding must be fixed before release (for an
  operating system package, usually by updating the base image), or added as a
  narrow, expiring exception with an owner and rationale in
  `.github/.trivyignore.yaml`.
- Dry runs push no images, so they do not scan images or collect their source.
