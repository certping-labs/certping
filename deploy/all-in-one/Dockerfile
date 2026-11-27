# syntax=docker/dockerfile:1.7
# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0

# CertPing all-in-one: the whole product in one container with its own PostgreSQL and Valkey, for a
# homelab, a trial or a small team. One volume (/var/lib/certping) holds the database, the secrets
# and the generated configuration. Production installs with more than one server use the Compose
# kit or the Helm chart instead; this image runs one of everything and cannot scale out.
#
# Built from the per-application images (not from source), so a release's all-in-one carries the
# same, signed application layers as its separate images. Build context: the repository root.
#
#   docker build -f deploy/all-in-one/Dockerfile --build-arg CERTPING_VERSION=0.0.1-beta -t certping .
#   docker run -d --name certping -p 80:80 -v certping:/var/lib/certping certping
#
# The application images default to the release named by CERTPING_VERSION (never :latest). The
# release workflow passes each image by digest (SERVER_IMAGE=...@sha256:...) instead.
ARG CERTPING_VERSION=0.0.1-beta
ARG SERVER_IMAGE=ghcr.io/certping-labs/certping-server:${CERTPING_VERSION}
ARG WEB_IMAGE=ghcr.io/certping-labs/certping-web:${CERTPING_VERSION}
ARG AGENT_IMAGE=ghcr.io/certping-labs/certping-agent:${CERTPING_VERSION}
ARG NOTIFIER_IMAGE=ghcr.io/certping-labs/certping-notifier:${CERTPING_VERSION}
ARG NODE_IMAGE=node:24.22.3-bookworm-slim@sha256:873f586f3794f52281bd039bf02c048a0be08fde619338f9941bad1eb6b34530
# caddy:2.11.9-builder
ARG CADDY_BUILDER_IMAGE=caddy:2.11.9-builder@sha256:cda07fe9d82728c7ac44d844306d435e98131423dc7b114f05a8a8ecfff94707

FROM ${SERVER_IMAGE} AS server
FROM ${WEB_IMAGE} AS web
FROM ${AGENT_IMAGE} AS agent
FROM ${NOTIFIER_IMAGE} AS notifier
FROM ${NODE_IMAGE} AS node

# Caddy 2.11.9 as the release binary is built (same build tags, static, stripped), with
# golang.org/x/net raised to 0.62.0: the release's 0.60.0 has fixable vulnerabilities
# (CVE-2026-78661, CVE-2026-97045). Cross-compiled on the build platform, so no emulation.
FROM --platform=$BUILDPLATFORM ${CADDY_BUILDER_IMAGE} AS caddy
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" XCADDY_SETCAP=0 \
    XCADDY_GO_BUILD_FLAGS="-trimpath -ldflags='-w -s' -tags=nobadger,nomysql,nopgx" \
    xcaddy build v2.11.9 --replace golang.org/x/net=golang.org/x/net@v0.62.0 --output /usr/bin/caddy

# Ubuntu 26.04 with a JRE 25: PostgreSQL 18, Valkey 9 (the BSD-licensed, Redis-compatible store
# the server uses) and supervisor come from Ubuntu's own archive (valkey-server is in main).
FROM eclipse-temurin:25-jre@sha256:4ed132f6832e9804b123e89a849a7b4502756ae64a4ee08ebab939d9d5d0a9fa

ENV DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        postgresql-18 postgresql-client-18 valkey-server supervisor \
        curl ca-certificates openssl xxd gosu libcap2-bin; \
    rm -rf /var/lib/apt/lists/*; \
    ln -s /usr/lib/postgresql/18 /usr/lib/postgresql/current; \
    # One account per service, so none can read another's environment file or data. The server
    # and the bundled agent share one, as they share the encrypted secrets directory. postgres
    # and valkey keep the accounts their packages create.
    for svc in certping:185 certping-notifier:186 certping-web:187 certping-caddy:188; do \
        name="${svc%%:*}"; id="${svc##*:}"; \
        groupadd --system --gid "$id" "$name"; \
        useradd --system --uid "$id" --gid "$id" --home /nonexistent --no-create-home \
            --shell /usr/sbin/nologin "$name"; \
    done; \
    usermod --home /var/lib/certping certping; \
    mkdir -p /opt/certping /var/lib/certping /var/log/certping; \
    chown certping:certping /var/lib/certping /var/log/certping

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=caddy /usr/bin/caddy /usr/local/bin/caddy
# Application files belong to root and are read only (0444 files, 0555 directories).
COPY --from=server --chown=0:0 /app/app.jar /opt/certping/server.jar
COPY --from=notifier --chown=0:0 /app/app.jar /opt/certping/notifier.jar
COPY --from=agent --chown=0:0 /app/app.jar /opt/certping/agent.jar
COPY --from=web --chown=0:0 /app /opt/certping/web
RUN set -eux; \
    # Next.js writes its image cache under .next/cache: point it at a directory the web user
    # owns (created by the entrypoint), outside the read-only application tree.
    rm -rf /opt/certping/web/.next/cache; \
    ln -s /var/cache/certping-web /opt/certping/web/.next/cache; \
    find /opt/certping -type d -exec chmod 0555 {} +; \
    find /opt/certping -type f -exec chmod 0444 {} +

COPY deploy/all-in-one/supervisord.conf /etc/certping/supervisord.conf
COPY deploy/all-in-one/Caddyfile /etc/certping/Caddyfile
COPY deploy/all-in-one/entrypoint.sh /usr/local/bin/certping-entrypoint
COPY deploy/all-in-one/certping-admin /usr/local/bin/certping-admin
COPY apps/server/scripts/jwt-keygen.sh /usr/local/bin/certping-jwt-keygen
RUN chmod 0755 /usr/local/bin/certping-entrypoint /usr/local/bin/certping-admin /usr/local/bin/certping-jwt-keygen; \
    # Caddy binds 80 and 443 as the certping user.
    setcap cap_net_bind_service=+ep /usr/local/bin/caddy

# CertPing's LICENSE and NOTICE and the third-party notices for everything in this image,
# generated by .github/scripts/third-party-notices.sh. The Ubuntu packages' own copyright files stay in
# /usr/share/doc/<package>/copyright.
COPY --chown=0:0 licenses/LICENSE licenses/NOTICE licenses/all-in-one/THIRD-PARTY-NOTICES.txt /licenses/certping/

# The base image's created, version and ref.name labels describe Ubuntu; clear them (the release
# workflow sets version and revision).
LABEL org.opencontainers.image.created="" \
      org.opencontainers.image.version="" \
      org.opencontainers.image.ref.name="" \
      org.opencontainers.image.title="certping" \
      org.opencontainers.image.description="CertPing all-in-one: server, web, notifier, agent, PostgreSQL, Valkey and Caddy in one container" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/certping-labs/certping" \
      org.opencontainers.image.url="https://github.com/certping-labs/certping" \
      org.opencontainers.image.documentation="https://github.com/certping-labs/certping" \
      org.opencontainers.image.vendor="Seaionl Inc." \
      name="certping" \
      vendor="Seaionl Inc."

# Where people and remote agents reach this installation. http://localhost for a laptop; a DNS name
# with https:// for a server, where Caddy obtains the certificate from Let's Encrypt (80 and 443
# must be reachable).
ENV CERTPING_URL=http://localhost
# The release this image is (the build ARG above). The entrypoint hands it to the server, which
# shows it as the agent image tag in the "Add agent" command.
ARG CERTPING_VERSION
ENV CERTPING_VERSION=${CERTPING_VERSION}
# Default heap shares for the three JVMs; the container should have 4 GB.
ENV CERTPING_SERVER_HEAP=1200m CERTPING_AGENT_HEAP=512m CERTPING_NOTIFIER_HEAP=384m

VOLUME /var/lib/certping
EXPOSE 80 443
HEALTHCHECK --interval=30s --timeout=10s --start-period=240s --retries=5 \
  CMD curl -fsS http://localhost:8080/actuator/health/readiness >/dev/null && \
      curl -fsS http://localhost:3000/api/health >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/certping-entrypoint"]
