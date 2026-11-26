// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { BadgeProps } from "@/components/ui/badge";
import { getProviderPresentation } from "@/lib/credential-providers";
import type {
  CredentialReference,
  DeploymentRecord,
} from "@/types/cert-manager";

export function formatDeploymentStatusLabel(value: string): string {
  return value
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export function getDeploymentStatusBadgeVariant(
  status: string,
): BadgeProps["variant"] {
  switch (status.toUpperCase()) {
    case "SUCCESS":
    case "COMPLETED":
      return "success";
    case "FAILED":
    case "FAILED_VALIDATION":
    case "FAILED_DEPLOYMENT":
      return "destructive";
    case "PENDING":
    case "IN_PROGRESS":
    case "DEPLOYING":
      return "warning";
    default:
      return "secondary";
  }
}

export function getTriggeredBy(deployment: DeploymentRecord): string {
  const triggeredBy = deployment.metadata?.triggeredBy;
  return typeof triggeredBy === "string" ? triggeredBy : "-";
}

export function getTriggeredByBadgeVariant(
  triggeredBy: string,
): BadgeProps["variant"] {
  switch (triggeredBy.toUpperCase()) {
    case "AUTO":
      return "info";
    case "MANUAL":
      return "warning";
    default:
      return "secondary";
  }
}

export function getSnapshotHealthLabel(deployment: DeploymentRecord): string {
  if (deployment.userMessage) {
    return "Needs attention";
  }

  switch (deployment.status.toUpperCase()) {
    case "SUCCESS":
    case "COMPLETED":
      return "Healthy snapshot";
    case "PENDING":
    case "IN_PROGRESS":
    case "DEPLOYING":
      return "In flight";
    default:
      return "Captured";
  }
}

export function getProviderCardDetails(
  providerValue: string | undefined,
  fallbackLabel: string,
): { label: string; logo: string | undefined } {
  const presentation = getProviderPresentation(providerValue);
  return {
    label: presentation.label || fallbackLabel,
    logo: presentation.logo ?? undefined,
  };
}

export function getCredentialPresentation(
  credential: CredentialReference | undefined,
  deployment: DeploymentRecord | null | undefined,
): { title: string; subtitle: string; logo: string | undefined } {
  const providerValue = credential?.targetType || credential?.provider;
  const fallbackTitle =
    credential?.description ||
    deployment?.deploymentCredentialXref ||
    "Not linked";
  const providerPresentation = getProviderCardDetails(
    providerValue,
    fallbackTitle,
  );

  return {
    title: fallbackTitle,
    subtitle:
      credential?.targetType ||
      credential?.provider ||
      deployment?.deploymentCredentialXref ||
      "Deployment credential",
    logo: providerPresentation.logo,
  };
}
