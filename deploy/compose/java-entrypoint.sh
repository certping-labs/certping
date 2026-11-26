#!/bin/sh
# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0

# Entrypoint wrapper for the CertPing Java images (server, notifier, agent). It trusts extra CA
# certificates, then starts the service exactly as the image's own entrypoint does.
#
# CERTPING_EXTRA_CA_CERTS: path inside the container to a PEM file with one or more CA
# certificates (a private ACME CA such as step-ca, a TLS-inspecting proxy, an internal SMTP relay).
# They are added to a copy of the JVM's trust store in /tmp, and JAVA_TOOL_OPTIONS points the JVM
# at that copy. Unset or empty: nothing changes. The all-in-one image does the same in its own
# entrypoint. Kept identical in deploy/compose and in the files/ folder of both Helm charts.
set -eu

if [ -n "${CERTPING_EXTRA_CA_CERTS:-}" ]; then
  if [ ! -r "$CERTPING_EXTRA_CA_CERTS" ]; then
    echo "certping: CERTPING_EXTRA_CA_CERTS=$CERTPING_EXTRA_CA_CERTS is not a readable file" >&2
    exit 2
  fi
  if [ -z "${JAVA_HOME:-}" ]; then
    JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")"
  fi
  keytool="$JAVA_HOME/bin/keytool"
  [ -x "$keytool" ] || keytool="$(command -v keytool)"
  # A unique name: containers of one pod can share /tmp.
  store="$(mktemp "${TMPDIR:-/tmp}/certping-truststore.XXXXXX")"
  cp -L "$JAVA_HOME/lib/security/cacerts" "$store"
  chmod 0600 "$store"
  split_dir="$(mktemp -d)"
  awk -v dir="$split_dir" '/-----BEGIN CERTIFICATE-----/{n++} n{print > (dir "/ca-" n ".pem")} /-----END CERTIFICATE-----/{close(dir "/ca-" n ".pem")}' \
    "$CERTPING_EXTRA_CA_CERTS"
  count=0
  for pem in "$split_dir"/ca-*.pem; do
    [ -e "$pem" ] || continue
    count=$((count + 1))
    "$keytool" -importcert -noprompt -alias "certping-extra-$count" -file "$pem" \
      -keystore "$store" -storepass changeit >/dev/null 2>&1
  done
  rm -rf "$split_dir"
  if [ "$count" -eq 0 ]; then
    echo "certping: no certificates found in CERTPING_EXTRA_CA_CERTS=$CERTPING_EXTRA_CA_CERTS" >&2
    exit 2
  fi
  JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Djavax.net.ssl.trustStore=$store -Djavax.net.ssl.trustStorePassword=changeit"
  export JAVA_TOOL_OPTIONS
  echo "certping: trusting $count extra CA certificate(s) from $CERTPING_EXTRA_CA_CERTS" >&2
fi

if [ "$#" -gt 0 ]; then
  exec "$@"
fi
# The images' own entrypoint: /bin/sh -c 'exec java -javaagent:${OTEL_JAVAAGENT_PATH} ${JAVA_OPTS} -jar app.jar'
# JAVA_OPTS is split into words on purpose, as the image does.
# shellcheck disable=SC2086
exec java "-javaagent:${OTEL_JAVAAGENT_PATH}" ${JAVA_OPTS:-} -jar app.jar
