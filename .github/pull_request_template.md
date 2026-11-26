<!-- Title: Conventional Commit style, for example "fix(agent): retry ACME order on 429". -->

## What and why

<!-- What changes, and the problem it solves. Link the issue: "Fixes #123". -->

## How it was tested

<!-- Commands you ran (for example `make server-ci`) and anything checked by hand.
     User-facing change? Add a screenshot or a short recording. -->

## Impact

<!-- Delete the lines that do not apply; keep "None" for the rest. -->

- Security: <!-- keys, credentials, auth, tenant boundaries, new network calls, or "None" -->
- Dependencies or workflows: <!-- new or upgraded dependency, Dockerfile, chart or .github change, or "None" -->
- Release and compatibility: <!-- migration, config change, API change, upgrade step, or "None" -->
- Docs and operations: <!-- docs updated, runbook or alert change, or "None" -->

## Checklist

- [ ] Tests added or updated for the change (no tests that only exist to turn CI green)
- [ ] No secrets, private keys, customer data, real hostnames or internal endpoints in code, tests, fixtures, screenshots or logs
- [ ] Private keys and credentials are never logged, returned by an API or written to audit records
- [ ] Docs updated if behavior, config or an API changed
- [ ] Breaking change? Add `!` to the title (for example `feat(server)!: ...`) and describe the upgrade path below
- [ ] New trivy exception? It has an owner, a statement and an expiry in `.github/.trivyignore.yaml`
- [ ] Commits are signed off (`git commit -s`, DCO, see CONTRIBUTING.md)

## Breaking changes and upgrade notes

<!-- "None" if none. -->
