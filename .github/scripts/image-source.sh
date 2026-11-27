#!/usr/bin/env bash
# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0

# Collects the corresponding source of the operating system packages and libraries in one release
# image. The Release workflow publishes it next to the image as
# ghcr.io/certping-labs/<image>-source:<version> (GPL-3.0 section 6(d), LGPL-3.0 section 4,
# GPL-2.0 section 3).
#
#   image-source.sh [--libvips] [--temurin] <out-dir> <trivy report>...
#
# The trivy reports (image-scan.sh, one per platform) list every operating system package in the
# image with its source package; the source of every one of them is collected, whatever its
# license. Written to <out-dir>:
#   rpm/          Red Hat UBI images: the source RPM of each package, from the UBI CDN. The CDN
#                 keeps superseded builds that the repository metadata (and so dnf) no longer
#                 lists, so they are fetched by file name. Red Hat's signatures are checked with
#                 the keys in VERIFY_IMAGE (the image's base image, by digest).
#   deb/          Ubuntu images: each source package (.dsc and the files it lists) from the
#                 Ubuntu archive, or from Launchpad, which keeps every published version, once the
#                 archive has dropped it; files are checked against the .dsc.
#   libvips/      with --libvips (the image contains sharp's libvips): the archives and patches
#                 in licenses/components/sharp-libvips-<version>/sources.txt (patches from the
#                 copies in patches/ beside it), checked by SHA-256,
#                 and librsvg-<version>-crates.tar with the crates.io crates of librsvg's
#                 Cargo.lock, each checked against the lockfile.
#   temurin/      with --temurin (the image is built on eclipse-temurin): the source archive of
#                 its Temurin JDK release, as JAVA_VERSION in the image configuration names it,
#                 from licenses/components/temurin/sources.txt, checked by SHA-256.
#   SOURCES.txt   one line per file: SHA-256, path, and where it came from.
set -euo pipefail

libvips=0
temurin=0
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --libvips) libvips=1 ;;
    --temurin) temurin=1 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done
if [[ $# -lt 2 ]]; then
  echo "usage: $0 [--libvips] [--temurin] <out-dir> <trivy report>..." >&2
  exit 2
fi
out="$1"
shift
reports=("$@")
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
curl=(curl -fsSL --retry 5 --retry-delay 5)
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$out"
index="$out/SOURCES.txt"
{
  echo "# Corresponding source collected by .github/scripts/image-source.sh."
  echo "# Columns: SHA-256, file, where it was downloaded from."
  echo "# Check the files: grep -v '^#' SOURCES.txt | awk '{ print \$1 \"  \" \$2 }' | sha256sum -c"
} > "$index"

record() {
  printf '%s  %s  %s\n' "$(sha256sum "$out/$1" | cut -d' ' -f1)" "$1" "$2" >> "$index"
}

fail() {
  echo "::error::$*" >&2
  exit 1
}

single() {
  local values
  values="$(jq -r "$1" "${reports[@]}" | sort -u)"
  [[ -n "$values" && "$values" != *$'\n'* ]] || fail "the reports disagree or say nothing about $1: ${values:-none}"
  printf '%s' "$values"
}

family="$(single '.Metadata.OS.Family // empty')"
os_version="$(single '.Metadata.OS.Name // empty')"
os_packages='.Results[]? | select(.Class == "os-pkgs") | .Packages[]? | select((.SrcName // "") != "")'
missing=()

case "$family" in
  redhat)
    [[ -n "${VERIFY_IMAGE:-}" ]] || fail "set VERIFY_IMAGE to the image, by digest, to check the source RPM signatures with"
    major="${os_version%%.*}"
    cdn="https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi$major/$major"
    mkdir -p "$out/rpm"
    jq -r "$os_packages | \"\(.SrcName)-\(.SrcVersion)-\(.SrcRelease).src.rpm\"" "${reports[@]}" \
      | sort -u > "$work/srpms"
    while read -r srpm; do
      letter="$(printf '%s' "${srpm:0:1}" | tr '[:upper:]' '[:lower:]')"
      url=""
      for arch in x86_64 aarch64; do
        for repo in baseos appstream codeready-builder; do
          candidate="$cdn/$arch/$repo/source/SRPMS/Packages/$letter/$srpm"
          if curl -fsI --retry 3 -o /dev/null "$candidate"; then
            url="$candidate"
            break 2
          fi
        done
      done
      if [[ -z "$url" ]]; then
        missing+=("$srpm")
        continue
      fi
      "${curl[@]}" -o "$out/rpm/$srpm" "$url"
      record "rpm/$srpm" "$url"
    done < "$work/srpms"
    [[ ${#missing[@]} -eq 0 ]] || fail "source RPMs not found on the UBI CDN: ${missing[*]}"

    in_image=()
    for f in "$out"/rpm/*.src.rpm; do in_image+=("/src/$(basename "$f")"); done
    docker run --rm --network none --entrypoint rpm -v "$out/rpm:/src:ro" "$VERIFY_IMAGE" \
      -K "${in_image[@]}" > "$work/signatures" || true
    if grep -v ': digests signatures OK$' "$work/signatures" || \
       [[ "$(wc -l < "$work/signatures")" -ne "${#in_image[@]}" ]]; then
      fail "source RPM signature check failed (output above)"
    fi
    echo "Collected ${#in_image[@]} source RPMs, signatures checked"
    ;;

  ubuntu)
    mkdir -p "$out/deb"
    pool=()
    for component in main universe restricted multiverse; do
      pool+=("https://archive.ubuntu.com/ubuntu/pool/$component")
    done
    jq -r "$os_packages | [.SrcName, ((if (.SrcEpoch // 0) > 0 then \"\(.SrcEpoch):\" else \"\" end)
             + .SrcVersion + (if (.SrcRelease // \"\") != \"\" then \"-\(.SrcRelease)\" else \"\" end))] | @tsv" \
      "${reports[@]}" | sort -u > "$work/sources"
    while IFS=$'\t' read -r pkg version; do
      plain="${version#*:}"
      dir="deb/${pkg}_$plain"
      dsc="${pkg}_$plain.dsc"
      if [[ "$pkg" == lib?* ]]; then prefix="${pkg:0:4}"; else prefix="${pkg:0:1}"; fi
      # The archive's pool is fast but drops superseded versions after a while; Launchpad keeps
      # every version but answers slowly, so it is the fallback.
      base=""
      for candidate in "${pool[@]/%//$prefix/$pkg}" \
                       "https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/$pkg/${version//:/%3A}"; do
        if curl -fsIL --retry 3 -o /dev/null "$candidate/$dsc"; then
          base="$candidate"
          break
        fi
      done
      if [[ -z "$base" ]]; then
        missing+=("$pkg=$version")
        continue
      fi
      mkdir -p "$out/$dir"
      "${curl[@]}" -o "$out/$dir/$dsc" "$base/$dsc"
      record "$dir/$dsc" "$base/$dsc"
      awk '/^Checksums-Sha256:/ { on = 1; next } on && /^ / { print $1, $3; next } { on = 0 }' \
        "$out/$dir/$dsc" > "$work/files"
      [[ -s "$work/files" ]] || fail "$dsc lists no files"
      while read -r sum file; do
        "${curl[@]}" -o "$out/$dir/$file" "$base/$file"
        echo "$sum  $out/$dir/$file" | sha256sum -c --quiet - || fail "$file does not match $dsc"
        record "$dir/$file" "$base/$file"
      done < "$work/files"
    done < "$work/sources"
    [[ ${#missing[@]} -eq 0 ]] || fail "source packages not found in the Ubuntu archive or on Launchpad: ${missing[*]}"
    echo "Collected $(wc -l < "$work/sources") Ubuntu source packages"
    ;;

  *)
    fail "no source collection for operating system family '$family'"
    ;;
esac

# Eclipse Temurin images name their JDK release in JAVA_VERSION (jdk-<version>); the UBI OpenJDK
# images set JAVA_VERSION to the major version only and are covered by their source RPMs.
java_version="$(jq -r '.Metadata.ImageConfig.config.Env[]? | select(startswith("JAVA_VERSION=jdk-")) | ltrimstr("JAVA_VERSION=")' \
  "${reports[@]}" | sort -u)"
if [[ "$temurin" == 0 ]]; then
  [[ -z "$java_version" ]] || fail "the image contains Temurin $java_version: collect its source with --temurin"
else
  [[ -n "$java_version" && "$java_version" != *$'\n'* ]] \
    || fail "--temurin: expected one JAVA_VERSION=jdk-... in the reports, found: ${java_version:-none}"
  grep -qF "Eclipse Temurin OpenJDK ${java_version#jdk-} JRE" "$root/licenses/all-in-one/THIRD-PARTY-NOTICES.txt" \
    || fail "the all-in-one notices name another Temurin release than $java_version: update TEMURIN_VERSION in .github/scripts/third-party-notices.mjs"
  list="$root/licenses/components/temurin/sources.txt"
  read -r _ file sum url < <(awk -v v="$java_version" '!/^#/ && $1 == v' "$list") \
    || fail "no source archive for Temurin $java_version in ${list#"$root"/}"
  mkdir -p "$out/temurin"
  "${curl[@]}" -o "$out/temurin/$file" "$url"
  echo "$sum  $out/temurin/$file" | sha256sum -c --quiet - || fail "$file does not match its SHA-256 in ${list#"$root"/}"
  record "temurin/$file" "$url"
  echo "Collected the source of Temurin $java_version"
fi

sharp_libvips="$(jq -r '.Results[]? | select(.Class == "lang-pkgs") | .Packages[]?
  | select(.Name | test("^@img/sharp-libvips-linux(musl)?-")) | .Version' "${reports[@]}" | sort -u)"
if [[ "$libvips" == 0 ]]; then
  [[ -z "$sharp_libvips" ]] || fail "the image contains @img/sharp-libvips $sharp_libvips: collect its source with --libvips"
  exit 0
fi
[[ -n "$sharp_libvips" && "$sharp_libvips" != *$'\n'* ]] \
  || fail "--libvips: expected one @img/sharp-libvips version in the reports, found: ${sharp_libvips:-none}"
list="$root/licenses/components/sharp-libvips-$sharp_libvips/sources.txt"
[[ -f "$list" ]] || fail "no ${list#"$root"/} for @img/sharp-libvips $sharp_libvips"

mkdir -p "$out/libvips"
rsvg=""
patches="$(dirname "$list")/patches"
while read -r library file sum url; do
  # Patches are generated by their hosts on request and may change byte for byte; the copies
  # beside sources.txt are the ones checked in.
  if [[ -f "$patches/$file" ]]; then
    cp "$patches/$file" "$out/libvips/$file"
  else
    "${curl[@]}" -o "$out/libvips/$file" "$url"
  fi
  echo "$sum  $out/libvips/$file" | sha256sum -c --quiet - || fail "$file ($library) does not match its SHA-256 in ${list#"$root"/}"
  record "libvips/$file" "$url"
  if [[ "$library" == "rsvg" && "$file" == *.tar.xz ]]; then rsvg="$file"; fi
done < <(grep -v '^#' "$list")
[[ -n "$rsvg" ]] || fail "no librsvg archive in ${list#"$root"/}"

# librsvg is written in Rust: its build downloads the crates in Cargo.lock from crates.io.
lock="$(tar -tJf "$out/libvips/$rsvg" | awk '/^[^\/]*\/Cargo\.lock$/ && !seen { print; seen = 1 }')"
[[ -n "$lock" ]] || fail "$rsvg has no Cargo.lock"
tar -xJOf "$out/libvips/$rsvg" "$lock" > "$work/Cargo.lock"
awk -F' = ' '
  function flush() {
    if (source ~ /^registry\+https:\/\/github\.com\/rust-lang\/crates\.io-index$/ && checksum != "") print name, version, checksum
    else if (source != "") bad = bad " " name
  }
  /^\[\[package\]\]$/ { flush(); name = version = source = checksum = ""; next }
  { gsub(/"/, "", $2) }
  $1 == "name" { name = $2 }
  $1 == "version" { version = $2 }
  $1 == "source" { source = $2 }
  $1 == "checksum" { checksum = $2 }
  END { flush(); if (bad != "") { print "crates from other sources:" bad > "/dev/stderr"; exit 1 } }
' "$work/Cargo.lock" > "$work/crates"
mkdir -p "$work/crates.d"
while read -r crate version sum; do
  "${curl[@]}" -o "$work/crates.d/$crate-$version.crate" "https://static.crates.io/crates/$crate/$crate-$version.crate"
  echo "$sum  $work/crates.d/$crate-$version.crate" | sha256sum -c --quiet - || fail "crate $crate $version does not match Cargo.lock"
done < "$work/crates"
crates="libvips/${rsvg%.tar.xz}-crates.tar"
tar -cf "$out/$crates" -C "$work/crates.d" --sort=name .
record "$crates" "https://static.crates.io/crates/ ($(wc -l < "$work/crates") crates of $lock, checked against it)"
echo "Collected the libvips sources of @img/sharp-libvips $sharp_libvips and $(wc -l < "$work/crates") librsvg crates"
