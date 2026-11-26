#!/usr/bin/env bash
# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0

# Regenerates the third-party notices that every CertPing image carries in /licenses/certping/:
#   licenses/<image>/THIRD-PARTY-NOTICES.txt   for server, agent, notifier, web and all-in-one
#   apps/<app>/licenses/                       LICENSE, NOTICE and that file, in each build context
#
#   .github/scripts/third-party-notices.sh            regenerate (commit the result)
#   .github/scripts/third-party-notices.sh --check    exit 1 if the committed files are stale (for CI)
#
# Needs Maven with the apps' dependencies in the local repository (run a build first, or set
# MVN_OFFLINE= to let Maven download), JDK 25, Node.js 24 and pnpm with apps/web installed
# (pnpm install). Run it after any dependency change, then commit what changed.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
check=0
[[ "${1:-}" == "--check" ]] && check=1

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

offline="${MVN_OFFLINE--o}"
args=()
for app in server agent notifier; do
  # shellcheck disable=SC2086
  (cd "$root/apps/$app" && mvn $offline -B -q dependency:list -DincludeScope=runtime \
    -DoutputAbsoluteArtifactFilename=true -Dsort=true -DoutputFile="$work/$app.txt" >"$work/$app.log" 2>&1) \
    || { cat "$work/$app.log" >&2; echo "mvn dependency:list failed for $app" >&2; exit 1; }
  args+=(--maven "$app=$work/$app.txt")
done

(cd "$root/apps/web" && pnpm licenses list --prod --json >"$work/web.json")
args+=(--pnpm "$work/web.json")

if [[ "$check" == 1 ]]; then
  node "$root/.github/scripts/third-party-notices.mjs" "${args[@]}" --out "$work/out" >/dev/null
  stale=0
  for rel in licenses/LICENSE licenses/NOTICE \
             licenses/{server,agent,notifier,web,all-in-one}/THIRD-PARTY-NOTICES.txt \
             apps/{server,agent,notifier,web}/licenses/{LICENSE,NOTICE,THIRD-PARTY-NOTICES.txt}; do
    if ! cmp -s "$work/out/$rel" "$root/$rel"; then
      echo "stale: $rel" >&2
      stale=1
    fi
  done
  if [[ "$stale" == 1 ]]; then
    echo "Third-party notices are out of date: run .github/scripts/third-party-notices.sh and commit the result." >&2
    exit 1
  fi
  echo "Third-party notices are up to date."
else
  node "$root/.github/scripts/third-party-notices.mjs" "${args[@]}"
fi
