#!/usr/bin/env bash
# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0

# Prints a fresh RS256 key set as env lines for the server, for local runs and for seeding a
# new environment's secret store. See docs/operations.md#jwt-signing-keys for rotating keys in a live environment.
#
# Usage: scripts/jwt-keygen.sh [kid] [issuer]
set -euo pipefail

kid="${1:-local-$(date +%Y%m%d)}"
issuer="${2:-http://localhost:8080}"

# The kid is written into shell lines and JSON as is, so only plain characters are allowed.
[[ "$kid" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "kid may contain only letters, digits, '.', '_' and '-'" >&2; exit 2; }

command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

# Assigning to a name the caller exported keeps it exported, which would hand the private key to
# every program started below.
unset key private_one_line

key="$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null)"
exponent="$(printf '%s\n' "$key" | openssl rsa -noout -text 2>/dev/null | awk '/^publicExponent/ {print $2}')"
[[ "$exponent" == "65537" ]] || { echo "unexpected public exponent: $exponent" >&2; exit 1; }

modulus="$(printf '%s\n' "$key" | openssl rsa -noout -modulus 2>/dev/null | cut -d= -f2 \
  | xxd -r -p | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
private_one_line="$(printf '%s\n' "$key" | awk 'NF { printf "%s\\n", $0 }')"

# Single quotes keep every value literal for both a shell `source` and a Compose env_file.
cat <<ENV
JWT_ISSUER='${issuer}'
JWT_AUDIENCE='certping-api'
JWT_SIGNING_KEY_ID='${kid}'
JWT_SIGNING_PRIVATE_KEY='${private_one_line}'
JWT_PUBLISHED_KEYS='{"keys":[{"kty":"RSA","kid":"${kid}","use":"sig","alg":"RS256","n":"${modulus}","e":"AQAB"}]}'
ENV
