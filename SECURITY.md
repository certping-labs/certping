# Security policy

This policy covers the code and deployment artifacts in this repository: the
CertPing open-source, self-hosted product (web app, server, agent, notifier,
Helm charts, Docker Compose and Terraform kits, CI and release workflows).
The hosted CertPing service at certping.com, run by Seaionl Inc., is governed
by its own terms and has its own security and support processes; see
[Hosted CertPing](#hosted-certping) below.

CertPing handles private keys, CA credentials and deployment credentials, so
security reports come before other project work.

## Reporting a vulnerability

Please report vulnerabilities privately. Do not open a public issue, pull
request or discussion, and do not post details anywhere public before a fix is
available. There are two private channels:

1. Email `security@certping.com`. This address is for security
   vulnerabilities only; it reaches the maintainers listed in
   [MAINTAINERS.md](MAINTAINERS.md). Questions go to
   [GitHub Discussions](https://github.com/certping-labs/certping/discussions),
   and general bugs and feature requests to GitHub issues. See
   [SUPPORT.md](SUPPORT.md) for every support channel.
2. GitHub private vulnerability reporting: open the repository's **Security**
   tab and select **Report a vulnerability**. It opens a private advisory
   draft that only you and the maintainers can see.

Include what is affected (app, version or commit), how to reproduce it, and the
impact you expect. A proof of concept is welcome. If you want credit, say the
name or handle to use.

**Do not send secrets.** Never include real private keys, certificates with
private keys, API tokens, passwords, credentials, customer data or production
hostnames in a report. A description of where they leak, or a redacted sample,
is enough. If a proof of concept needs a key, generate a throwaway one.

Email is not encrypted end to end. If a report is too sensitive for plain
email, say so in a first message without details and we will agree on a
channel.

## What to expect

CertPing is a pre-1.0 project run by a small core team. There is no dedicated security
team and no service level agreement; what follows are aims, not promises.

- We aim to acknowledge a report within a week.
- After that, we tell you whether we consider it a vulnerability and how
  severe, and we keep you informed while we work on it.
- A confirmed critical or high issue is fixed as soon as we can; other
  confirmed issues are fixed in a normal release.

If you hear nothing within two weeks, send one reminder to the same address or
add a comment to your private advisory. If you still hear nothing, you may
treat the report as unacknowledged and follow the disclosure guidance below.

## Severity

We rate reports with CVSS v3.1 as a guide and adjust for how CertPing is
deployed. Roughly:

| Severity | Examples |
| --- | --- |
| Critical | An unauthenticated attacker can read or export private keys or credentials, run code on the server or agent, or cross into another organization's data. |
| High | An authenticated user can escalate privileges, read another organization's data or keys, or cause a certificate to be issued or deployed somewhere it should not be. |
| Medium | Information disclosure without keys or credentials, missing authorization on a low-impact action, denial of service by an authenticated user, or a security control that can be bypassed only with unusual configuration. |
| Low | Hardening gaps, verbose errors, issues that need an already compromised administrator, and findings with no practical attack. |

Reports in the scope below are handled as vulnerabilities whatever their
rating. Hardening suggestions are welcome as normal issues or pull requests.

## Supported versions

CertPing is pre-1.0. v0.0.1-beta is a public beta. There is no long-term support
branch.

| Version | Security fixes |
| --- | --- |
| The latest `v0.x` release | yes |
| Older releases and pre-releases | no, please upgrade |

Fixes are made on `main` and shipped in a new `v0.x` release; they are not
backported to earlier releases.

Before 1.0, a security fix may ship with other changes and may need a
configuration change; the release notes will say so. Once `v1.0.0` ships, this
section will list which release lines receive fixes and for how long.

## Coordinated disclosure

We ask for coordinated disclosure: give us the chance to fix the issue before
it is published.

- We agree on a disclosure date with you. The default is 90 days after the
  report, or earlier once a fix is released, whichever comes first.
- If a fix takes longer, we will explain why and propose a new date. If the
  issue is being exploited, we may publish sooner, with a workaround.
- We credit reporters in the advisory and the release notes unless they ask
  not to be named. We do not currently pay bounties.

### CVEs and advisories

When a fix for a confirmed vulnerability in this repository is released, the
maintainers may publish a GitHub Security Advisory for it, with affected and
fixed versions, credit and any workaround, and may request a CVE through the
advisory where one is appropriate. Not every report results in an advisory or
a CVE: a dependency issue that does not affect CertPing, a misconfiguration the
documentation already warns about, or a hardening change is explained in the
response and the release notes instead.

## Safe harbor

We support good-faith security research on the code in this repository and on
CertPing installations you run yourself or are authorized to test. When you:

- test only systems you own or have written authorization to test;
- avoid privacy violations, data destruction and degrading other people's
  service;
- do not access, change or keep data beyond what is needed to show the issue;
- report the issue privately as described above and give us reasonable time
  to fix it;

then, as far as it is within Seaionl Inc.'s control, we treat that research as
authorized and will not pursue legal action against you for it, and we will
work with you to understand and resolve the issue. This statement is made in
good faith by the project; it is not legal advice, it cannot bind third
parties (including the operators of the services CertPing integrates with and
the providers of the infrastructure an installation runs on), and it does not
cover conduct that breaks the law in your jurisdiction. It applies to this
repository and to self-hosted installations you are authorized to test only.
Testing the hosted CertPing service at certping.com requires explicit written
authorization from Seaionl Inc. first; without it, that testing is not covered
by this policy.

## Scope

### In scope

The code in this repository: the web app, server, agent, notifier, Helm
charts, Docker Compose and Terraform kits, and the CI and release workflows.
The areas we most want reports on: private key generation, storage
and export; credential handling and secret stores; organization and permission
boundaries; agent token and gateway authentication; certificate validation;
SSRF through discovery and deployment integrations; the integrity of release
artifacts and images.

### Out of scope

- The hosted CertPing service at certping.com and Seaionl Inc.'s own
  infrastructure; see [Hosted CertPing](#hosted-certping).
- Third-party provider infrastructure that an installation connects to
  (certificate authorities, DNS providers, cloud platforms, Kubernetes
  distributions, load balancers). It is outside CertPing's control. A CertPing
  bug in how it talks to such a provider is in scope.
- Vulnerabilities in third-party dependencies that are already public, unless
  the report explains how CertPing is affected through them. Dependabot and
  the Security workflow track public dependency issues; a report that shows an
  exploitable path through CertPing is in scope and welcome.
- Issues that need a compromised host, root access or a malicious maintainer.
- Reports from automated scanners with no analysis of whether CertPing is
  affected.
- Denial of service by sheer traffic volume, social engineering and physical
  attacks.

## Hosted CertPing

The hosted CertPing service at certping.com is a separate offering of
Seaionl Inc. This policy does
not cover it and makes no promises about it. If you are unsure whether
something you found is in the open-source code or only in a hosted service,
report it to `security@certping.com` and say so; the maintainers will route it.

## Security measures in this repository

[.github/RELEASING.md](.github/RELEASING.md) describes signed images, SBOMs,
provenance, the vulnerability scan every image passes before it is released,
and how to verify them. Each week the Image scan workflow scans the images of
the latest release again and reports new findings in the repository's Security
tab.
[docs/self-hosting.md#privacy-and-telemetry](docs/self-hosting.md#privacy-and-telemetry) describes what a self-hosted installation
sends out and what it does not.
[docs/architecture.md#key-custody-and-trust](docs/architecture.md#key-custody-and-trust) describes where private keys are
generated and stored, when the server can read them, and the trust model of
agent tokens. Sign-in rate limits and account lockout are in
[docs/operations.md](docs/operations.md#rate-limits).

## Known limitations

A targeted review was made before v0.0.1-beta; it was not a full audit. These points
are known and are good starting places for a researcher:

- The notifier's HTTP API and the internal gRPC port (50051) require the
  internal token (`CERTPING_INTERNAL_TOKEN`), and the gRPC port opens only on
  `INTERNAL_GRPC_BIND_ADDRESS`. Both still use plaintext on the internal
  network, so keep them there, and in Kubernetes keep the chart's
  NetworkPolicies on ([docs/architecture.md](docs/architecture.md#internal-grpc)).
- An agent token is trusted for its whole organization: every agent of an
  organization can receive every job of that organization, including
  credential handles, and can post results for it. Use one organization per
  trust zone ([docs/architecture.md#key-custody-and-trust](docs/architecture.md#trust-model-of-agent-tokens)).
- In the all-in-one and Compose installs, and in Helm with the bundled agent,
  the server and the bundled agent share one local key store and its key, so
  the server host can read the private keys
  ([docs/architecture.md#key-custody-and-trust](docs/architecture.md#when-the-server-can-read-a-key)).
- First-run setup has no setup token. With no bootstrap admin configured,
  whoever reaches the setup screen first becomes the admin
  ([docs/architecture.md#key-custody-and-trust](docs/architecture.md#first-run-setup)).
- Kubernetes deployment replaces a Secret of the same name even when another
  tool manages it, and the all namespaces option copies the private key into
  every namespace.
- Agents connect to hosts that operators configure (F5, EJBCA, Smallstep and
  others), often on private networks. Do not share one agent's network
  position between organizations that should not reach each other's systems.
- Organization scoping in the server's data access, and trust-chain
  validation of issued and discovered certificates, were not reviewed end to
  end.
