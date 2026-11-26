// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  CLIENT_LOG_PATH,
  SERVER_ROUTED_PREFIXES,
} from "@/lib/logger/client-log-path";

const repo = resolve(__dirname, "../../../../..");
const read = (path: string) => readFileSync(resolve(repo, path), "utf8");

/** The prefixes a Caddyfile's `@server path ...` matcher sends to the server. */
function caddyServerPrefixes(caddyfile: string): string[] {
  const line = caddyfile
    .split("\n")
    .map((l) => l.trim())
    .find((l) => l.startsWith("@server path "));
  if (!line) throw new Error("no @server path matcher");
  return line
    .slice("@server path ".length)
    .split(/\s+/)
    .map((p) => p.replace(/\/\*$/, ""));
}

/** The prefixes the certping chart's Ingress sends to the server. */
function ingressServerPrefixes(template: string): string[] {
  const match = template.match(/range list ((?:"[^"]+"\s*)+)/);
  if (!match) throw new Error("no server path list in the ingress template");
  return [...match[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
}

/** Caddy `path /x/*` and Ingress `Prefix /x` both match /x itself and anything below /x/. */
const routedToServer = (path: string, prefixes: readonly string[]) =>
  prefixes.some((p) => path === p || path.startsWith(`${p}/`));

describe("client log path", () => {
  const kits: Array<[string, string[]]> = [
    [
      "all-in-one Caddyfile",
      caddyServerPrefixes(read("deploy/all-in-one/Caddyfile")),
    ],
    [
      "Compose Caddyfile",
      caddyServerPrefixes(read("deploy/compose/Caddyfile")),
    ],
    [
      "Helm Ingress",
      ingressServerPrefixes(
        read("deploy/charts/certping/templates/ingress-data.yaml"),
      ),
    ],
  ];

  it.each(kits)("reaches the web app through the %s", (_kit, prefixes) => {
    expect(prefixes).toEqual([...SERVER_ROUTED_PREFIXES]);
    expect(routedToServer(CLIENT_LOG_PATH, prefixes)).toBe(false);
  });

  it("would be shadowed under /api, which is why it moved", () => {
    expect(routedToServer("/api/logger", SERVER_ROUTED_PREFIXES)).toBe(true);
  });
});
