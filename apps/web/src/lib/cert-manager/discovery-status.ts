// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { humanizeEnum } from "@/lib/humanize";
import type {
  DiscoveryConfigStatus,
  DiscoveryFailedScope,
  DiscoveryRunResponse,
} from "@/types/discovery";

/**
 * Discovery config statuses that represent a finished run. Once a config reaches
 * one of these, polling should stop because the backend will not advance the
 * state further without a new scan being triggered.
 */
export const TERMINAL_DISCOVERY_CONFIG_STATUSES: readonly DiscoveryConfigStatus[] =
  ["COMPLETE", "PARTIAL", "FAILED", "CREDENTIAL_INVALID", "CANCELLED"];

/** True when a discovery config's scan has reached a terminal state. */
export function isTerminalDiscoveryConfigStatus(
  status: DiscoveryConfigStatus | null | undefined,
): boolean {
  return status != null && TERMINAL_DISCOVERY_CONFIG_STATUSES.includes(status);
}

/**
 * Discovery config statuses that represent an in-flight scan. Used to decide
 * whether the saved-config list should keep polling for live updates (idle
 * `READY` configs should not trigger polling).
 */
export const ACTIVE_DISCOVERY_CONFIG_STATUSES: readonly DiscoveryConfigStatus[] =
  ["STARTED", "IN_PROGRESS"];

/** True when a discovery config currently has a scan running. */
export function isActiveDiscoveryConfigStatus(
  status: DiscoveryConfigStatus | null | undefined,
): boolean {
  return status != null && ACTIVE_DISCOVERY_CONFIG_STATUSES.includes(status);
}

/** Statuses where the last run ended in an error the user should look at. */
export function isFailedDiscoveryConfigStatus(
  status: DiscoveryConfigStatus | null | undefined,
): boolean {
  return status === "FAILED" || status === "CREDENTIAL_INVALID";
}

export type DiscoveryStatusBadgeVariant =
  "success" | "destructive" | "warning" | "secondary";

/** Badge tone for a saved config's status; a cancelled run is neutral, not a failure. */
export function discoveryConfigStatusVariant(
  status: DiscoveryConfigStatus,
): DiscoveryStatusBadgeVariant {
  if (status === "COMPLETE") return "success";
  if (status === "PARTIAL") return "warning";
  if (isFailedDiscoveryConfigStatus(status)) return "destructive";
  if (isActiveDiscoveryConfigStatus(status)) return "warning";
  return "secondary";
}

/** "Credential invalid", "Cancelled": statuses read as words, not enums. */
export function discoveryConfigStatusLabel(
  status: DiscoveryConfigStatus,
): string {
  return humanizeEnum(status);
}

export const PARTIAL_DISCOVERY_MESSAGE =
  "Partial: some accounts or namespaces failed. Certificates in them were left as they were.";

/**
 * Shown when a run carries no message of its own. A scan is cancelled by an
 * admin as well as by turning discovery off, so the copy names no cause.
 */
export function discoveryConfigStatusFallbackMessage(
  status: DiscoveryConfigStatus,
): string {
  if (status === "PARTIAL") return PARTIAL_DISCOVERY_MESSAGE;
  return status === "CANCELLED"
    ? "This scan was cancelled."
    : "Discovery status is waiting for the next agent update.";
}

const FAILED_SCOPE_TYPE_LABELS: Record<string, string> = {
  AWS_ACCOUNT: "AWS account",
  AWS_REGION: "AWS region",
  AZURE_VAULT: "Key Vault",
  K8S_NAMESPACE: "Namespace",
  K8S_CLUSTER: "Cluster",
};

/** "AWS account 123456789012 (DISCOVERY_AWS_ACCOUNT_ACCESS_DENIED)". */
export function formatFailedScope(scope: DiscoveryFailedScope): string {
  const type = scope.scopeType?.trim() || "";
  const kind = type
    ? (FAILED_SCOPE_TYPE_LABELS[type] ?? humanizeEnum(type))
    : "Unknown scope";
  const id = scope.scopeId?.trim();
  const code = scope.errorCode?.trim();
  return `${kind}${id ? ` ${id}` : ""}${code ? ` (${code})` : ""}`;
}

/** The failed scopes of a run, tolerant of a server that does not send them. */
export function discoveryFailedScopes(
  config: Pick<DiscoveryRunResponse, "failedScopes">,
): DiscoveryFailedScope[] {
  return Array.isArray(config.failedScopes)
    ? config.failedScopes.filter(
        (scope): scope is DiscoveryFailedScope =>
          Boolean(scope) && typeof scope === "object",
      )
    : [];
}

/**
 * The status line for a run. A PARTIAL run always says it is partial, then
 * lists what failed when the server returned it.
 */
export function discoveryConfigStatusMessage(
  config: Pick<DiscoveryRunResponse, "status" | "message" | "failedScopes">,
): string {
  const own = config.message?.trim();
  if (config.status !== "PARTIAL") {
    return own || discoveryConfigStatusFallbackMessage(config.status);
  }
  const scopes = discoveryFailedScopes(config);
  if (scopes.length === 0) {
    return own && own !== PARTIAL_DISCOVERY_MESSAGE
      ? `${PARTIAL_DISCOVERY_MESSAGE} ${own}`
      : PARTIAL_DISCOVERY_MESSAGE;
  }
  const shown = scopes.slice(0, 5).map(formatFailedScope).join(", ");
  const more = scopes.length > 5 ? ` and ${scopes.length - 5} more` : "";
  return `Partial: some accounts or namespaces failed: ${shown}${more}. Certificates in them were left as they were.`;
}
