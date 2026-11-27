# Licenses shipped in the CertPing images

Every CertPing image carries these files in `/licenses/certping/`:

- `LICENSE`: the Apache License 2.0 that covers all of CertPing (a copy of the root `LICENSE`).
  There is no second CertPing license.
- `NOTICE`: CertPing's notice file (a copy of the root `NOTICE`).
- `THIRD-PARTY-NOTICES.txt`: every third-party component in that image, with its version and
  license, the license elections CertPing makes, the NOTICE files and copyright statements the
  components carry, and the full license texts.

## Layout

| Path | What it is |
|------|------------|
| `server/`, `agent/`, `notifier/`, `web/`, `all-in-one/` | `THIRD-PARTY-NOTICES.txt` for each image (generated) |
| `LICENSE`, `NOTICE` | Copies of the root files (generated) |
| `texts/` | Full license texts, from the SPDX license list (EDL-1.0 from eclipse.org, the PostgreSQL License from PostgreSQL, GPL-2.0 with the Classpath Exception from OpenJDK) |
| `components/` | Texts for components that are not application dependencies: the Node.js license, the Valkey license, the font licenses and the OpenTelemetry Java agent's bundled notices |
| `components/caddy-2.8.4/` | `modules.txt` (what `caddy build-info` prints) and, per Go module and the Go toolchain, the license, NOTICE and patent files of its source at that version |
| `../apps/<app>/licenses/` | Copies of `LICENSE`, `NOTICE` and the app's `THIRD-PARTY-NOTICES.txt` inside each app's Docker build context (generated) |

Each app's Dockerfile copies `apps/<app>/licenses/` to `/licenses/certping/`; the all-in-one
Dockerfile copies `LICENSE`, `NOTICE` and `all-in-one/THIRD-PARTY-NOTICES.txt` from here. Files
under `/licenses` that a base image provides are left as they are.

## Regenerating

The notices come from the dependencies that actually ship:

- Java apps: `mvn dependency:list -DincludeScope=runtime` (what Spring Boot packs into
  `BOOT-INF/lib`, without optional dependencies), with each artifact's licenses from its POM and
  the `LICENSE` and `NOTICE` files inside its jar.
- Web app: `pnpm licenses list --prod --json`, with each package's `LICENSE` and `NOTICE` files.
  Native packages (sharp, libvips, the Next.js compiler) are listed as their Linux x64 and arm64
  variants, which the image installs.

After changing a dependency, a base image or a bundled component:

```sh
export JAVA_HOME=<JDK 25>
(cd apps/web && pnpm install)
.github/scripts/third-party-notices.sh            # rewrite the generated files, then commit them
.github/scripts/third-party-notices.sh --check    # exit 1 if the committed files are stale (for CI)
```

The Caddy files come from the module source archives on proxy.golang.org at the versions in
`modules.txt` (the Go toolchain's from github.com/golang/go at its release tag): every LICENSE,
COPYING, NOTICE, COPYRIGHT and PATENTS file in the archive, except test data, packaging files
and files for other operating systems. When the Caddy version changes, replace `modules.txt` with
the new binary's `caddy build-info` and collect the files again; the generator fails if a module
has none.

The script runs Maven offline by default; set `MVN_OFFLINE=` to let it download. It needs JDK
25, Maven, Node.js 24 and pnpm. Versions of runtime components (OpenJDK, Node.js, PostgreSQL,
Valkey, Caddy, the OpenTelemetry agent, the fonts) are written in
`.github/scripts/third-party-notices.mjs`; update them there when a Dockerfile changes them.

## Elections

Where a component is offered under a choice of licenses, CertPing uses and redistributes it under
one of them, listed in section 3 of each `THIRD-PARTY-NOTICES.txt`. Among them: logback under
EPL-2.0, jakarta.annotation-api and jakarta.transaction-api under EPL-2.0, jakarta.mail-api and
angus-mail under EDL-1.0. sharp's libvips is used under the LGPL-3.0-or-later, and users may
replace it (see its section in `web/THIRD-PARTY-NOTICES.txt`).
