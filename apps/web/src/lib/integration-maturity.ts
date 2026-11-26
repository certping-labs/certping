// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Which integrations have a real-target or end-to-end test, mirroring the
 * Status column of docs/integrations.md. Everything not listed here is tested
 * only against mocked provider APIs and is labelled "Beta" wherever users pick
 * it (deployment target types, credential pickers, CA pickers, discovery).
 *
 * Tested end to end today (deploy/e2e-lab):
 * - ACME DNS-01 (the Let's Encrypt choice) with the CertPing DNS provider
 * - Kubernetes Secret deployment
 * - Kubernetes discovery
 * - Email notifications
 *
 * When a new integration gets an end-to-end test, add its API value here and
 * update docs/integrations.md in the same change.
 */
export type IntegrationKind =
  "DEPLOYMENT" | "DNS" | "CA" | "DISCOVERY" | "NOTIFICATION";

const END_TO_END_TESTED: Record<IntegrationKind, ReadonlySet<string>> = {
  DEPLOYMENT: new Set(["KUBERNETES_SECRETS"]),
  DNS: new Set(["CERTPING"]),
  CA: new Set(["LETS_ENCRYPT"]),
  DISCOVERY: new Set(["KUBERNETES_SECRETS"]),
  NOTIFICATION: new Set(["EMAIL"]),
};

const ANY_END_TO_END_TESTED: ReadonlySet<string> = new Set(
  Object.values(END_TO_END_TESTED).flatMap((values) => [...values]),
);

function normalize(apiValue: string | null | undefined): string {
  return (apiValue ?? "").trim().toUpperCase();
}

/** True when this integration has no real-target or end-to-end test yet. */
export function isBetaIntegration(
  kind: IntegrationKind,
  apiValue: string | null | undefined,
): boolean {
  const value = normalize(apiValue);
  if (!value) return false;
  return !END_TO_END_TESTED[kind].has(value);
}

/**
 * Same check when the kind is not known (a saved credential in a picker). An
 * API value is tested only if it is end-to-end tested in some kind; no API
 * value is shared between a tested and an untested kind.
 */
export function isBetaProviderApiValue(
  apiValue: string | null | undefined,
): boolean {
  const value = normalize(apiValue);
  if (!value) return false;
  return !ANY_END_TO_END_TESTED.has(value);
}

export const BETA_INTEGRATION_DESCRIPTION =
  "Beta: tested against mocked provider APIs only, not yet verified against the live service.";
