#!/usr/bin/env bash
# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0

# Produces the values for rotating the JWT signing key by hand, in any secret store. It never
# prints a private key: that goes to a file only you can read. Steps are in docs/operations.md#jwt-signing-keys.
#
# Usage:
#   scripts/jwt-rotate.sh add <new-kid> <out-dir>   < current JWT_PUBLISHED_KEYS
#       Writes a new key pair to <out-dir>: JWT_SIGNING_KEY_ID, JWT_SIGNING_PRIVATE_KEY, and
#       JWT_PUBLISHED_KEYS holding the current keys plus the new one.
#   scripts/jwt-rotate.sh keep <kid>                < current JWT_PUBLISHED_KEYS
#       Prints JWT_PUBLISHED_KEYS reduced to that one key, for the final step.
set -euo pipefail

usage() {
  sed -n '5,10p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

# Reads a key set on stdin and prints it back after checking it is a public-only RSA set with
# a kid on every key.
# Extra arguments: "add <kid> <jwk-json>" appends a key, "keep <kid>" keeps only that key.
edit_key_set() {
  python3 -c '
import json, sys
PRIVATE = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
def refuse_constant(name):
    raise ValueError(name)
try:
    keys = json.load(sys.stdin, parse_constant=refuse_constant).get("keys")
except (ValueError, AttributeError, RecursionError):
    sys.exit("the current key set is not a JSON object with a \"keys\" list")
if not isinstance(keys, list) or not keys:
    sys.exit("the current key set has no keys")
for key in keys:
    if not isinstance(key, dict) or key.get("kty") != "RSA" or not all(
            isinstance(key.get(field), str) and key[field] for field in ("kid", "n", "e")):
        sys.exit("every key in the current set must be an RSA key with a kid, n and e")
    if PRIVATE & key.keys():
        sys.exit("the current key set contains private key material; fix that first")
kids = [key["kid"] for key in keys]
action, kid = sys.argv[1], sys.argv[2]
if action == "add":
    if kid in kids:
        sys.exit("kid " + kid + " is already published")
    keys.append(json.loads(sys.argv[3])["keys"][0])
else:
    if kid not in kids:
        sys.exit("kid " + kid + " is not published")
    keys = [key for key in keys if key["kid"] == kid]
print(json.dumps({"keys": keys}, separators=(",", ":")))
' "$@"
}

case "${1:-}" in
  add)
    [[ $# -eq 3 && "$2" =~ ^[A-Za-z0-9._-]+$ ]] || usage
    kid="$2" out="$3"
    [[ ! -e "$out" ]] || { echo "$out already exists; use a new directory" >&2; exit 1; }
    current="$(cat)"
    umask 077
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    "$(dirname "$0")/jwt-keygen.sh" "$kid" unused > "$work/env"
    # Only the public half enters this shell; the private key is read in a subshell that starts
    # no programs, so it never lands in a child process's environment.
    # shellcheck disable=SC1091
    new_key="$(source "$work/env"; printf '%s' "$JWT_PUBLISHED_KEYS")"
    published="$(printf '%s' "$current" | edit_key_set add "$kid" "$new_key")"
    mkdir "$work/out"
    printf '%s' "$published" > "$work/out/JWT_PUBLISHED_KEYS"
    (
      # shellcheck disable=SC1091
      source "$work/env"
      printf '%s' "$JWT_SIGNING_KEY_ID" > "$work/out/JWT_SIGNING_KEY_ID"
      printf '%s' "$JWT_SIGNING_PRIVATE_KEY" > "$work/out/JWT_SIGNING_PRIVATE_KEY"
    )
    mv "$work/out" "$out"
    echo "wrote $out/JWT_PUBLISHED_KEYS, $out/JWT_SIGNING_KEY_ID and $out/JWT_SIGNING_PRIVATE_KEY"
    echo "delete $out once the private key is stored"
    ;;
  keep)
    [[ $# -eq 2 && -n "$2" ]] || usage
    edit_key_set keep "$2"
    ;;
  *)
    usage
    ;;
esac
