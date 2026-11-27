#!/usr/bin/env bash
# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0

# Pushes the source collected by image-source.sh to the registry as an OCI artifact, one layer per
# file (oras pull restores the files), and writes the release asset that names it.
#
#   image-source-push.sh <source-dir> <reference> <image name> <index file>
#   image-source-push.sh source ghcr.io/certping-labs/certping-server-source:0.1.0 certping-server source-server.txt
#
# <index file> is SOURCES.txt with a first line "# Published as <reference>@<digest>", which the
# release metadata and notes read. Needs oras (./oras, or ORAS) logged in to the registry, and
# VERSION and REPO_URL in the environment.
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <source-dir> <reference> <image name> <index file>" >&2
  exit 2
fi
dir="$1"
ref="$2"
image="$3"
index="$(pwd)/$4"
oras="$(cd "$(dirname "${ORAS:-./oras}")" && pwd)/$(basename "${ORAS:-./oras}")"
: "${VERSION:?}" "${REPO_URL:?}"

cd "$dir"
files=(SOURCES.txt)
while IFS= read -r f; do files+=("$f"); done < <(find . -type f ! -path ./SOURCES.txt -printf '%P\n' | sort)

"$oras" push "$ref" "${files[@]}" \
  --artifact-type application/vnd.certping.image-source.v1 \
  --annotation "org.opencontainers.image.title=$image-source" \
  --annotation "org.opencontainers.image.description=Corresponding source of the operating system packages and GPL and LGPL components in $image:$VERSION" \
  --annotation "org.opencontainers.image.version=$VERSION" \
  --annotation "org.opencontainers.image.source=$REPO_URL"
digest="$("$oras" manifest fetch --descriptor "$ref" | jq -r .digest)"
[[ "$digest" == sha256:* ]] || { echo "::error::could not read the digest of $ref" >&2; exit 1; }

{
  echo "# Published as $ref@$digest"
  cat SOURCES.txt
} > "$index"
echo "Pushed $(( ${#files[@]} - 1 )) files to ${ref}@$digest"
