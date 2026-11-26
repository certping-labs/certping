// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Where the browser sends its log records: the web app's own route
 * (src/app/web-api/logger/route.ts). It must stay outside the paths that Caddy
 * (deploy/all-in-one/Caddyfile, deploy/compose/Caddyfile) and the Helm Ingress
 * send to the server, or the server answers instead of the web app.
 */
export const CLIENT_LOG_PATH = "/web-api/logger";

/** Path prefixes every kit routes to the server; everything else reaches the web app. */
export const SERVER_ROUTED_PREFIXES = [
  "/api",
  "/.well-known",
  "/oauth2",
  "/login/oauth2",
] as const;
