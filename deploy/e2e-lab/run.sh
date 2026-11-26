#!/usr/bin/env bash
# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0

# CertPing end-to-end lab: start a clean lab, run every flow, print a pass or fail summary.
#   ./run.sh            fresh lab (removes the previous lab's data), run, leave it running
#   ./run.sh --keep     reuse the running lab and its data
#   ./run.sh --down     stop the lab and remove its data
# Uses the image in CERTPING_IMAGE (default certping-allinone:dev). Build it from the repository
# root first (or run `make images`):
#   CERTPING_VERSION=dev docker compose -f deploy/compose/docker-compose.yml build
#   docker build -f deploy/all-in-one/Dockerfile --build-arg CERTPING_VERSION=dev -t certping-allinone:dev .
set -euo pipefail
cd "$(dirname "$0")"

image="${CERTPING_IMAGE:-certping-allinone:dev}"
if [[ "${1:-}" != "--down" ]] && ! docker image inspect "$image" >/dev/null 2>&1; then
  echo "Image $image not found. Build it first (see the top of this script, or run make images)." >&2
  exit 2
fi

if [[ "${1:-}" == "--down" ]]; then
  docker compose down -v --remove-orphans
  rm -rf .work
  exit 0
fi

if [[ "${1:-}" != "--keep" ]]; then
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf .work
fi
mkdir -p .work

echo "Starting DNS, test CA and mailbox"
docker compose up -d dnsapi coredns pebble mailpit
for _ in $(seq 1 30); do
  docker compose cp pebble:/test/certs/pebble.minica.pem .work/pebble-ca.pem >/dev/null 2>&1 && break
  sleep 1
done

echo "Starting Kubernetes (k3s) and CertPing"
docker compose up -d k3s certping
for _ in $(seq 1 60); do
  curl -fsS -o /dev/null http://localhost:8090/api/v1/deployment-info && break
  sleep 5
done

python3 -u e2e.py
echo
echo "CertPing: http://localhost:8090 (admin password in .work/admin-password)"
echo "Mailbox:  http://localhost:8025"
