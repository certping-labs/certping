#!/usr/bin/env bash
# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0

# Builds the Compose kit of one release, certping-compose-<version>.zip, for the release assets.
# Runs on the release runner (GNU sed and cp, zip, Docker Compose).
#
#   compose-bundle.sh <version> <out-dir> [<app>=<image>@sha256:<digest> ...]
#   compose-bundle.sh 0.1.0 dist server=ghcr.io/certping-labs/certping-server@sha256:...
#
# The zip holds deploy/compose (the tracked files) with LICENSE and NOTICE. In its
# docker-compose.yml the four CertPing images are pinned to <version>, and to the digest given
# for each app, so the kit runs exactly the images the release verified. The build sections
# (which point into the source tree) are removed, and the README says how the kit differs from
# the one in the repository. Without digests (a dry run) the images are pinned by tag only.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <version> <out-dir> [<app>=<image>@sha256:<digest> ...]" >&2
  exit 2
fi
version="$1"
out="$(mkdir -p "$2" && cd "$2" && pwd)"
shift 2
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
apps=(web server agent notifier)

declare -A digest=()
for arg in "$@"; do
  app="${arg%%=*}"
  ref="${arg#*=}"
  [[ "$ref" == *@sha256:* ]] || { echo "$app: not pinned by digest: $ref" >&2; exit 1; }
  digest[$app]="@${ref#*@}"
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
kit="$work/certping-compose-$version"
mkdir -p "$kit"
(cd "$root/deploy/compose" && git ls-files -z . | xargs -0 -I{} cp --parents {} "$kit/")
rm -f "$kit/.gitignore"
cp "$root/LICENSE" "$root/NOTICE" "$kit/"

compose="$kit/docker-compose.yml"
for app in "${apps[@]}"; do
  pinned="certping-$app:$version${digest[$app]:-}"
  sed -i -E "s#(image: .*/)certping-$app:\\\$\\{CERTPING_VERSION:-[^}]*\\}\$#\\1$pinned#" "$compose"
  grep -Eq "^    image: .*/$pinned\$" "$compose" || { echo "no image line for $app in docker-compose.yml" >&2; exit 1; }
done
# Drop each service's build section: a key at service level and the lines indented under it.
awk '
  /^    build:/ { skip = 1; next }
  skip && /^      / { next }
  { skip = 0; print }
' "$compose" > "$work/compose.yml"
mv "$work/compose.yml" "$compose"
sed -i -E "s/\\\$\\{CERTPING_VERSION:-[^}]*\\}/$version/g" "$compose"
if grep -nE 'CERTPING_VERSION:-|^    build:|context: \.\./' "$compose"; then
  echo "docker-compose.yml still refers to the source tree or another version (lines above)" >&2
  exit 1
fi

pinned_to="$version"
if [[ ${#digest[@]} -eq ${#apps[@]} ]]; then pinned_to="$version and to the digests in the release notes"; fi
{
  cat <<EOF
# CertPing $version: Compose kit

This is the Compose kit of CertPing $version, from the release assets. It differs from
\`deploy/compose\` in the repository in three ways:

- The four CertPing images are pinned to $pinned_to, so the kit
  runs exactly the images that were released. \`CERTPING_VERSION\` in \`.env\` does not change them.
- It cannot build images from source: the build sections are removed. Clone the repository for that.
- To upgrade, download the kit of the new release, copy your \`.env\` into it, run
  \`./setup.sh --upgrade\` and \`docker compose up -d\`.

Where this README says \`deploy/compose\` or links into the repository, see
https://github.com/certping-labs/certping/tree/v$version.

EOF
  cat "$kit/README.md"
} > "$work/README.md"
mv "$work/README.md" "$kit/README.md"

(
  cd "$kit"
  touch .env
  REDIS_PASSWORD=check docker compose config --quiet
  rm .env
)

rm -f "$out/certping-compose-$version.zip"
(cd "$work" && zip -qr -X "$out/certping-compose-$version.zip" "certping-compose-$version")
echo "Wrote $out/certping-compose-$version.zip"
