#!/usr/bin/env bash
# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0

# End-to-end check of a running Compose install: sign in, create an organization, wait for the
# bundled agent, send it a command and get its answer back, create and revoke an agent token.
#
#   ./smoke-test.sh            # against CERTPING_URL from .env
#   CERTPING_URL=http://localhost:8088 SMOKE_PSQL="docker exec certping gosu postgres psql -d certping" \
#     SMOKE_ADMIN_FILE=/tmp/aio-admin ./smoke-test.sh      # against the all-in-one container
set -euo pipefail
cd "$(dirname "$0")"

url="${CERTPING_URL:-$(sed -nE "s/^CERTPING_URL='(.*)'$/\1/p" .env)}"
# How to run SQL against the installation's database (the heartbeat check reads a table).
psql_cmd="${SMOKE_PSQL:-docker compose exec -T postgres psql -U certping -d certping}"
json() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# The account this script signs in with. A fresh installation has no users, so the first run
# creates the Platform Super Admin through the same first-run setup the web app uses and keeps
# the generated password in .smoke-admin (mode 600) for later runs. An installation whose first
# admin was created by hand needs SMOKE_ADMIN_USERNAME and SMOKE_ADMIN_PASSWORD in the environment.
admin_file="${SMOKE_ADMIN_FILE:-.smoke-admin}"
if [[ -f "$admin_file" ]]; then
  admin_username="$(sed -nE 's/^username=(.*)$/\1/p' "$admin_file")"
  admin_password="$(sed -nE 's/^password=(.*)$/\1/p' "$admin_file")"
fi
# setup.sh writes a bootstrap admin into .env; use it when nothing else names an account.
if [[ -z "${SMOKE_ADMIN_USERNAME:-}" && -z "${admin_username:-}" && -f .env ]]; then
  admin_username="$(sed -nE "s/^BOOTSTRAP_SUPER_ADMIN_USERNAME='(.*)'$/\1/p" .env)"
  admin_password="$(sed -nE "s/^BOOTSTRAP_SUPER_ADMIN_PASSWORD='(.*)'$/\1/p" .env)"
fi
admin_username="${SMOKE_ADMIN_USERNAME:-${admin_username:-smoke_admin}}"
admin_password="${SMOKE_ADMIN_PASSWORD:-${admin_password:-}}"

step "deployment info"
info="$(curl -fsS "$url/api/v1/deployment-info" | tee /dev/stderr)"
grep -q '"agentTransport":"GATEWAY"' <<<"$info" || fail "server is not using the agent gateway"

if grep -q '"setupRequired":true' <<<"$info"; then
  step "first-run setup: create the Platform Super Admin"
  # Random, plus one of each class the password policy asks for (a random token can miss one).
  admin_password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')Aa1!"
  curl -fsS -X POST "$url/api/auth/setup" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$admin_username\",\"email\":\"$admin_username@smoke.example\",\"password\":\"$admin_password\",\"displayName\":\"Smoke test admin\"}" \
    | json 'd["message"]'
  (umask 077; printf 'username=%s\npassword=%s\n' "$admin_username" "$admin_password" > "$admin_file")
  curl -sS -X POST "$url/api/auth/setup" -H 'Content-Type: application/json' \
    -d '{"username":"second","email":"second@smoke.example","password":"Correct-Horse-Battery-9"}' \
    -o /dev/null -w '%{http_code}' | grep -q 409 || fail "setup did not close after the first admin"
  echo "setup closed after the first admin"
fi
[[ -n "$admin_password" ]] || fail "no admin password: set SMOKE_ADMIN_USERNAME and SMOKE_ADMIN_PASSWORD"

step "sign in as the Platform Super Admin"
sign_in() {
  curl -fsS -X POST "$url/api/auth/login" -H 'Content-Type: application/json' \
    -d "{\"identifier\":\"$admin_username\",\"password\":\"$admin_password\"}"
}
login="$(sign_in)"
token="$(echo "$login" | json 'd.get("token") or d.get("accessToken")')"
# The generated first password must be changed before anything else works (the server answers
# 403 PASSWORD_CHANGE_REQUIRED). Change it once and keep the new one for later runs.
if [[ "$(echo "$login" | json 'str(d.get("mustChangePassword", False)).lower()')" == "true" ]]; then
  new_password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')Aa1!"
  curl -fsS -o /dev/null -X POST "$url/api/auth/change-password" -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $token" \
    -d "{\"currentPassword\":\"$admin_password\",\"newPassword\":\"$new_password\",\"confirmPassword\":\"$new_password\"}"
  admin_password="$new_password"
  (umask 077; printf 'username=%s\npassword=%s\n' "$admin_username" "$admin_password" > "$admin_file")
  echo "first password changed (kept in $admin_file)"
  token="$(sign_in | json 'd.get("token") or d.get("accessToken")')"
fi
auth=(-H "Authorization: Bearer $token")

step "organization"
org="$(curl -fsS "${auth[@]}" "$url/api/v1/organizations" \
  | json '((d if isinstance(d, list) else d.get("content", [])) or [{}])[0].get("id", "")' || true)"
if [[ -z "$org" ]]; then
  org="$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' "$url/api/v1/organizations" \
    -d '{"name":"Smoke Test","domain":"smoke.example","orgType":"B2B"}' | json 'd["id"]')"
fi
echo "organization $org"

step "bundled agent heartbeat reaches the server"
for _ in $(seq 1 30); do
  # shellcheck disable=SC2086
  status="$($psql_cmd -tAc \
    "select overall_status from agent_health_status where organization_id = $org" || true)"
  [[ -n "$status" ]] && break
  sleep 5
done
[[ -n "$status" ]] || fail "no heartbeat from the bundled agent"
echo "agent health: $status"

step "server to agent and back: deep health check"
check="$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
  "$url/api/v1/agent/health/deep-checks" -d "{\"organizationId\":$org}")"
echo "$check"
for _ in $(seq 1 30); do
  state="$(curl -fsS "${auth[@]}" "$url/api/v1/agent/health/deep-checks?organizationId=$org" \
    | json '((d if isinstance(d, list) else d.get("content", [])) or [{}])[0].get("status", "")' || true)"
  [[ -n "$state" && "$state" != "PENDING" && "$state" != "REQUESTED" ]] && break
  sleep 2
done
echo "deep check status: ${state:-unknown}"
[[ -n "$state" && "$state" != "PENDING" && "$state" != "REQUESTED" ]] || fail "the agent did not answer the deep health check"

step "add an agent token and use it through the public URL"
created="$(curl -fsS -X POST "${auth[@]}" -H 'Content-Type: application/json' \
  "$url/api/v1/agent-tokens?organizationId=$org" -d "{\"name\":\"smoke\",\"serverUrl\":\"$url\"}")"
agent_token="$(echo "$created" | json 'd["value"]')"
token_id="$(echo "$created" | json 'd["token"]["id"]')"
curl -fsS -H "Authorization: Bearer $agent_token" "$url/api/v1/agent-gateway/whoami"; echo
curl -fsS -X DELETE "${auth[@]}" "$url/api/v1/agent-tokens/$token_id?organizationId=$org"
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $agent_token" "$url/api/v1/agent-gateway/whoami")"
[[ "$code" == "401" ]] || fail "a revoked token still works (HTTP $code)"
echo "revoked token refused"

step "web app"
curl -fsS -o /dev/null -w 'web HTTP %{http_code}\n' "$url/login"

echo
echo "PASS"
