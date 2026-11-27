#!/usr/bin/env bash
# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0

# Scans one release image for vulnerabilities in its operating system packages and application
# dependencies, one report per platform. The Release workflow runs it before an image is tagged;
# the weekly Image scan workflow runs it with --sarif on the latest release.
#
#   image-scan.sh [--sarif] <name> <out-dir> <platform>=<image reference> [...]
#   image-scan.sh server dist linux/amd64=ghcr.io/certping-labs/certping-server@sha256:...
#
# Writes <out-dir>/trivy-<name>-<os>-<arch>.json: trivy's JSON report, which also lists every
# package in the image with its source package (image-source.sh reads that). With --sarif it
# writes .sarif files for code scanning instead and never fails on findings.
#
# The policy is the Security workflow's: severities, ignore-unfixed and the mode (exit-code: 1
# blocking, 0 report-only) are read from .github/trivy.yaml, and the exceptions are in
# .github/.trivyignore.yaml. trivy.yaml itself is not passed: its skip-dirs (node_modules, ...)
# would hide the application dependencies inside the image. Every platform is scanned before the
# mode decides whether to fail. TRIVY is the trivy binary (default ./trivy).
set -euo pipefail

sarif=0
if [[ "${1:-}" == "--sarif" ]]; then
  sarif=1
  shift
fi
if [[ $# -lt 3 ]]; then
  echo "usage: $0 [--sarif] <name> <out-dir> <platform>=<image reference> [...]" >&2
  exit 2
fi
name="$1"
out="$2"
shift 2
trivy="${TRIVY:-./trivy}"
config=.github/trivy.yaml
mode=$(awk '/^exit-code:/ { print ($2 == "1") ? "blocking" : "report-only" }' "$config")
mode="${mode:-report-only}"
severity=$(awk '/^severity:/ { on = 1; next } on && /^ *- / { print $2; next } { on = 0 }' "$config" | paste -sd, -)
unfixed=$(awk '$1 == "ignore-unfixed:" { print $2 }' "$config")
[[ -n "$severity" ]] || { echo "no severity list in $config" >&2; exit 1; }
flags=(--scanners vuln --severity "$severity" --ignore-unfixed="${unfixed:-false}"
       --ignorefile .github/.trivyignore.yaml --exit-code 0 --image-src remote
       --timeout 30m --skip-version-check)

mkdir -p "$out"
total=0
for arg in "$@"; do
  platform="${arg%%=*}"
  ref="${arg#*=}"
  case "$ref" in *@sha256:*) ;; *) echo "::error::$name $platform is not pinned by digest: $ref" >&2; exit 1 ;; esac
  report="$out/trivy-$name-${platform//\//-}"
  if [[ "$sarif" == 1 ]]; then
    "$trivy" image "${flags[@]}" --platform "$platform" --format sarif --output "$report.sarif" "$ref"
    continue
  fi
  "$trivy" image "${flags[@]}" --list-all-pkgs --platform "$platform" --format json --output "$report.json" "$ref"
  "$trivy" convert --format table "$report.json"
  # Every CertPing image carries application dependencies (jars, npm packages); a report without
  # any means the scan did not see them.
  libraries=$(jq '[.Results[]? | select(.Class == "lang-pkgs") | .Packages[]?] | length' "$report.json")
  [[ "$libraries" -gt 0 ]] || { echo "::error::$name $platform: the scan found no application dependencies" >&2; exit 1; }
  found=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$report.json")
  echo "$name $platform: $found fixable $severity findings ($mode mode), $libraries application dependencies"
  total=$((total + found))
done

if [[ "$total" -gt 0 && "$mode" == "blocking" ]]; then
  echo "::error::$name has $total fixable $severity findings. Fix them (often a base image update), or accept each with a narrow, expiring entry and a statement in .github/.trivyignore.yaml."
  exit 1
fi
