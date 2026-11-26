// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { existsSync, readFileSync } from "node:fs";

/**
 * `pnpm test:integration` names its suites by path, in one hardcoded list in
 * package.json. A renamed or moved suite silently drops out of that run and
 * then fails the CI quality gate with an ENOENT - which `pnpm test`, `tsc` and
 * `eslint` all pass straight over, because none of them read that list. That is
 * exactly what happened when the credentials page test became the connections
 * panel test.
 *
 * <p>The list is a curated subset, not every `*.integration.test.tsx` in the
 * repo, so this asserts only that everything named in it exists. That is the
 * half that drifts.
 */
describe("test:integration manifest", () => {
  const script = (
    JSON.parse(readFileSync("package.json", "utf8")) as {
      scripts: Record<string, string>;
    }
  ).scripts["test:integration"];
  const paths = [...script.matchAll(/"([^"]+)"/g)].map((match) => match[1]);

  it("names at least one suite", () => {
    expect(paths.length).toBeGreaterThan(0);
  });

  it.each(paths)("names a suite that exists: %s", (path) => {
    expect(existsSync(path)).toBe(true);
  });
});
