#!/usr/bin/env bash
# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0

# Creates the Kubernetes Secret the certping chart reads, with fresh random keys.
#
#   ./create-secret.sh certping.example.com [namespace] [secret-name]
#
# Uses the same generator as the Compose install. The Secret holds the database and Valkey
# passwords (DB_PASSWORD, REDIS_PASSWORD), the password pepper, the JWT signing key, the agent
# gateway and secret-store keys and the first Platform Super Admin (BOOTSTRAP_SUPER_ADMIN_*, with
# a generated password). The server reads every key through envFrom. Back it up:
# without it the database's encrypted values cannot be read.
set -euo pipefail

domain="${1:?usage: create-secret.sh <domain> [namespace] [secret-name]}"
namespace="${2:-default}"
name="${3:-certping}"
here="$(cd "$(dirname "$0")" && pwd)"

command -v kubectl >/dev/null || { echo "kubectl is required" >&2; exit 1; }
if kubectl -n "$namespace" get secret "$name" >/dev/null 2>&1; then
  echo "Secret $namespace/$name already exists; not replacing it (its keys must not change)." >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
CERTPING_ENV_FILE="$work/env" "$here/../../compose/setup.sh" "$domain" >/dev/null

# setup.sh single-quotes every value for shells and Compose; kubectl takes them literally.
grep -E "^[A-Z0-9_]+=" "$work/env" | sed -E "s/^([A-Z0-9_]+)='(.*)'$/\1=\2/" > "$work/plain"

kubectl -n "$namespace" create secret generic "$name" --from-env-file="$work/plain"
admin_user="$(sed -nE "s/^BOOTSTRAP_SUPER_ADMIN_USERNAME=(.*)$/\1/p" "$work/plain")"
cat <<MSG
Created Secret $namespace/$name.

The server creates the first Platform Super Admin from this Secret at its first start:
  username: $admin_user
  password: kubectl -n $namespace get secret $name \\
              -o jsonpath='{.data.BOOTSTRAP_SUPER_ADMIN_PASSWORD}' | base64 -d; echo
You are asked to choose a new password at the first sign-in.
MSG
