# CertPing web app

The screens of CertPing. A Next.js app in TypeScript, built with pnpm. It has
no data of its own: the browser calls the CertPing server's API.

## Develop

From the repository root:

```bash
make web-setup   # install dependencies from the lockfile
make web-dev     # dev server on http://localhost:3000
make web-ci      # lint, typecheck, test and build, as CI does
```

Or inside `apps/web`:

```bash
pnpm install
pnpm dev
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

The dev server needs a CertPing server for the API. Run one with the Compose
kit ([deploy/compose](../../deploy/compose/README.md)) and point the web app at
it.

## Configuration

Copy [.env.example](.env.example) to `.env.local`. `NEXT_PUBLIC_*` values are
baked into the build and cannot change at runtime:

- `NEXT_PUBLIC_API_URL`: where the browser calls the API. Use `same-origin`
  when a reverse proxy routes `/api` to the server on the web app's origin, as
  the kits do.
- `CERTPING_API_TARGET`: optional, the API origin that `/api-proxy/*` forwards
  to in development.

## Tests

- Unit and component tests: Jest and Testing Library (`pnpm test`).

## More

- [docs/architecture.md](../../docs/architecture.md): how the web app fits with the rest.
