# What to use from a CertPing release

[GitHub Releases](https://github.com/certping-labs/certping/releases) lists the published versions.
GitHub tags have a leading `v`, for example `v0.0.1-beta`. Image and Helm chart versions use
`0.0.1-beta`.

## Install CertPing

| Your setup | What to use |
| --- | --- |
| Docker on a laptop or a single host | Run the [all-in-one image](../deploy/all-in-one/README.md#run). Docker pulls `ghcr.io/certping-labs/certping:0.0.1-beta` for you. It includes the web app, server, agent, notifier, PostgreSQL, Valkey and Caddy. |
| Separate containers on one server | Download `certping-compose-<version>.zip`. [The Compose guide](../deploy/compose/README.md#install-a-release) walks through unpacking and starting it. The kit pulls the four app images pinned to their published digests. |
| Kubernetes | Use the `certping` Helm chart from GHCR or download `certping-<version>.tgz`. Follow [the Helm install guide](../deploy/charts/certping/README.md#install) to create the bootstrap Secret and install the chart. |
| An extra agent for an existing install | Create a token in CertPing. Use the `certping-agent` [Docker image or Helm chart](agents.md#create-an-agent-token). The packaged chart is `certping-agent-<version>.tgz`. |

## Container images

The four component images are used by Compose and Helm. The `image-*.txt` files in the release
give the exact registry references by digest.

| GHCR package | What it runs |
| --- | --- |
| `certping` | The full all-in-one installation |
| `certping-web` | The browser interface |
| `certping-server` | The API, agent gateway, scheduler and work queue |
| `certping-agent` | Certificate issuance, renewal, deployment and discovery |
| `certping-notifier` | Email delivery |

## Source downloads

GitHub's **Source code (zip)** and **Source code (tar.gz)** are archives of the CertPing
repository at the release tag. Use them to read or build the project. CertPing's code is
licensed under [Apache 2.0](../LICENSE). [NOTICE](../NOTICE) and the
[image notices](../licenses/README.md) describe the licenses of bundled components.

Each `source-*.txt` is an index with a corresponding source package reference and file
checksums. Use it when inspecting or rebuilding third-party components shipped in an image.

| Index | GHCR source package | Contents |
| --- | --- | --- |
| `source-all-in-one.txt` | `certping-source` | Ubuntu package sources, Eclipse Temurin and libvips with its bundled libraries |
| `source-web.txt` | `certping-web-source` | Red Hat UBI source RPMs and libvips with its bundled libraries |
| `source-server.txt` | `certping-server-source` | Source RPMs for the server image's Red Hat UBI packages |
| `source-agent.txt` | `certping-agent-source` | Source RPMs for the agent image's Red Hat UBI packages |
| `source-notifier.txt` | `certping-notifier-source` | Source RPMs for the notifier image's Red Hat UBI packages |

To fetch a source package, use the exact reference in its index with `oras pull`. For example:

```sh
oras pull ghcr.io/certping-labs/certping-web-source:0.0.1-beta
```

## Verification files

| File | What it tells you |
| --- | --- |
| `sbom-*.cdx.json` | CycloneDX inventories of software dependencies |
| `trivy-*.json` | Vulnerability scan results by image and platform |
| `release-metadata.json` | The release commit, build run, digests, scan status and source references |
| `SHA256SUMS` and `SHA256SUMS.sigstore.json` | Checksums for attached files and the Sigstore signature over the checksum list |
| **Release attestation (json)** | GitHub's record linking the release tag, commit and assets when release immutability is enabled |

[Verify a release](../.github/RELEASING.md#verifying-a-release) for the commands to check
checksums, attestations and images.
