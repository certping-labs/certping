# Getting help

CertPing is maintained by a small team. Support for the open source project is best effort, with
no guaranteed response time.

## Where to ask

| You want to | Go to |
| --- | --- |
| Ask a question or share an idea | [GitHub Discussions](https://github.com/certping-labs/certping/discussions) |
| Report a bug or request a feature | [GitHub issues](https://github.com/certping-labs/certping/issues) |
| Get help with something that cannot be public | `support@certping.com` |
| Get paid support, an enterprise plan or managed cloud | [Paid options](#paid-options) |
| Report a code of conduct violation | `conduct@certping.com`. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). |
| Report a security vulnerability | `security@certping.com` or [GitHub private vulnerability reporting](https://github.com/certping-labs/certping/security/advisories/new). Never a public issue. See [SECURITY.md](SECURITY.md). |

Before you ask, check the [documentation](README.md#documentation) and the
[troubleshooting section](docs/operations.md#troubleshooting).

## Paid options

Seaionl Inc., the company behind CertPing, offers:

- **Paid support:** a guaranteed response time, help with rollout and upgrades, and a review of
  your setup.
- **Enterprise plans:** support for larger rollouts, and enterprise features as they ship.
- **Managed cloud:** a dedicated CertPing deployment set up and run with our team, with the agents
  in your network.

Contact us through [certping.com/enterprise](https://www.certping.com/enterprise/) or at
`sales@certping.com`. Paid services are covered by the
[CertPing terms](https://www.certping.com/terms/) and
[privacy policy](https://www.certping.com/privacy-policy/). Paying never unlocks or removes anything in this repository: the open
edition has no limits.

## What to include

- The CertPing version or image tag, for example `0.0.1-beta`.
- How you installed it: all-in-one container, Docker Compose, Helm or the Azure VM kit.
- What you did, what you expected and what happened.
- The CA, DNS provider or deployment target involved, if any.
- Relevant logs, for example from `docker logs certping`, with hostnames, account IDs and secrets
  removed.

## Never post secrets

Never post private keys, certificates with their keys, API tokens, agent tokens, passwords or
other credentials, in public or by email. If you posted one by mistake, revoke or rotate it.
