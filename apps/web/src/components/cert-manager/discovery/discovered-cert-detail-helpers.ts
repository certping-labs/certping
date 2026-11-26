// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { formatDiscoveryTargetLabel } from "@/lib/cert-manager/discovery-display";
import { formatDate, getRemainingDays } from "@/lib/utils";
import type {
  DiscoveredCertDetail,
  DiscoveryInventoryStatus,
  KubernetesAffectedWorkload,
  KubernetesBackendService,
  KubernetesDiscoveryData,
  KubernetesUsage,
} from "@/types/discovery";

export type DetailBadgeVariant =
  "success" | "destructive" | "secondary" | "outline" | "warning" | "info";

export interface OperationalFinding {
  title: string;
  description: string;
  variant: DetailBadgeVariant;
}

export interface KubernetesImpactValues {
  affectedHostnames: string[];
  affectedServices: string[];
  affectedWorkloads: string[];
}

export function compactValue(value: string | null | undefined): string {
  return value?.trim() || "-";
}

export function formatBoolean(value: boolean | null | undefined): string {
  if (value === true) return "Yes";
  if (value === false) return "No";
  return "Unknown";
}

export function formatUsageType(value: string | null): string {
  return value?.replaceAll("_", " ").toLowerCase() ?? "unknown usage";
}

export function formatTargetType(
  targetType: string | null | undefined,
): string {
  return formatDiscoveryTargetLabel(targetType);
}

export function getCertificateTitle(cert: DiscoveredCertDetail): string {
  return cert.domain ?? "Discovered certificate";
}

export function getExpirySummary(dateValue: string | null): {
  label: string;
  description: string;
  remainingDays: number | null;
  variant: DetailBadgeVariant;
} {
  const remainingDays = getRemainingDays(dateValue);

  if (remainingDays === null) {
    return {
      label: "Unknown",
      description: "No expiry timestamp was reported.",
      remainingDays,
      variant: "secondary",
    };
  }

  if (remainingDays < 0) {
    return {
      label: "Expired",
      description: `Expired ${Math.abs(remainingDays)} days ago.`,
      remainingDays,
      variant: "destructive",
    };
  }

  if (remainingDays <= 30) {
    return {
      label: `${remainingDays} days`,
      description: "Renewal should be prioritized.",
      remainingDays,
      variant: "warning",
    };
  }

  return {
    label: `${remainingDays} days`,
    description: "No near-term expiry pressure.",
    remainingDays,
    variant: "success",
  };
}

export function getInventoryBadgeVariant(
  status: DiscoveryInventoryStatus | null,
): DetailBadgeVariant {
  switch (status) {
    case "PRESENT":
      return "success";
    case "MISSING":
      return "destructive";
    case "UNKNOWN":
    default:
      return "secondary";
  }
}

export function getInventoryLabel(
  status: DiscoveryInventoryStatus | null,
): string {
  switch (status) {
    case "PRESENT":
      return "Present";
    case "MISSING":
      return "Missing";
    case "UNKNOWN":
    default:
      return "Unknown";
  }
}

export function getManagedLabel(managed: boolean | null): string {
  if (managed === true) return "Managed by CertPing";
  if (managed === false) return "External";
  return "Unknown";
}

export function getManagedBadgeVariant(
  managed: boolean | null,
): DetailBadgeVariant {
  if (managed === true) return "success";
  if (managed === false) return "warning";
  return "secondary";
}

export function formatService(service: KubernetesBackendService): string {
  const name =
    service.namespace && service.name
      ? `${service.namespace}/${service.name}`
      : compactValue(service.name);
  const port =
    service.portName || service.portNumber
      ? `:${service.portName ?? service.portNumber}`
      : "";
  return `${name}${port}`;
}

export function formatWorkload(workload: KubernetesAffectedWorkload): string {
  if (workload.namespace && workload.kind && workload.name) {
    return `${workload.namespace}/${workload.kind}/${workload.name}`;
  }
  return compactValue(workload.name);
}

export function uniqueValues(values: readonly string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim() !== "")));
}

export function getKubernetesImpactValues(
  data: KubernetesDiscoveryData | null,
): KubernetesImpactValues {
  if (!data) {
    return {
      affectedHostnames: [],
      affectedServices: [],
      affectedWorkloads: [],
    };
  }

  const serviceFallback = uniqueValues(
    data.usages.flatMap((usage) => usage.backendServices.map(formatService)),
  );
  const workloadFallback = uniqueValues(
    data.usages.flatMap((usage) => usage.affectedWorkloads.map(formatWorkload)),
  );

  return {
    affectedHostnames: data.impact?.affectedHostnames ?? [],
    affectedServices:
      data.impact?.affectedServices.length === 0
        ? serviceFallback
        : (data.impact?.affectedServices ?? serviceFallback),
    affectedWorkloads:
      data.impact?.affectedWorkloads.length === 0
        ? workloadFallback
        : (data.impact?.affectedWorkloads ?? workloadFallback),
  };
}

export function getOperationalFindings(
  cert: DiscoveredCertDetail,
): OperationalFinding[] {
  const findings: OperationalFinding[] = [];
  const expirySummary = getExpirySummary(cert.notAfter);
  const providerData = cert.providerData;
  const impactValues = getKubernetesImpactValues(providerData);

  if (cert.inventoryStatus === "MISSING") {
    findings.push({
      title: "Missing from latest scan",
      description: cert.missingSince
        ? `Not seen since ${formatDate(cert.missingSince)}. Confirm whether the provider resource was removed or the scan scope changed.`
        : "The latest discovery run did not find this provider resource.",
      variant: "destructive",
    });
  }

  if (expirySummary.remainingDays !== null && expirySummary.remainingDays < 0) {
    findings.push({
      title: "Certificate expired",
      description:
        "Replace or remove affected routes before users hit TLS failures.",
      variant: "destructive",
    });
  } else if (
    expirySummary.remainingDays !== null &&
    expirySummary.remainingDays <= 30
  ) {
    findings.push({
      title: "Expiry needs attention",
      description: `Expires in ${expirySummary.remainingDays} days. Prioritize renewal if this certificate is externally served.`,
      variant: "warning",
    });
  }

  if (cert.managed === false) {
    findings.push({
      title: "External certificate",
      description:
        "CertPing discovered this certificate but does not manage its lifecycle yet.",
      variant: "warning",
    });
  }

  if (providerData?.impact?.externallyServed) {
    findings.push({
      title: "Externally served",
      description:
        "This certificate is attached to a Kubernetes ingress path and can affect client traffic.",
      variant: "warning",
    });
  }

  if (impactValues.affectedServices.length > 0) {
    findings.push({
      title: `${impactValues.affectedServices.length} affected service${
        impactValues.affectedServices.length === 1 ? "" : "s"
      }`,
      description: impactValues.affectedServices.slice(0, 3).join(", "),
      variant: "warning",
    });
  }

  if (impactValues.affectedWorkloads.length > 0) {
    findings.push({
      title: `${impactValues.affectedWorkloads.length} affected workload${
        impactValues.affectedWorkloads.length === 1 ? "" : "s"
      }`,
      description: impactValues.affectedWorkloads.slice(0, 3).join(", "),
      variant: "warning",
    });
  }

  if (
    providerData &&
    (!providerData.usageComplete || !providerData.impactComplete)
  ) {
    findings.push({
      title: "Discovery context incomplete",
      description:
        "Usage or impact analysis is partial. Treat the dependency map as incomplete.",
      variant: "warning",
    });
  }

  if (findings.length === 0) {
    findings.push({
      title: "No immediate discovery issues",
      description:
        "The certificate is present, managed or low-risk, and not close to expiry.",
      variant: "success",
    });
  }

  return findings;
}

export function getKubernetesWarnings(data: KubernetesDiscoveryData): string[] {
  return [
    ...(data.usageComplete === false
      ? ["Usage discovery is incomplete for this scan."]
      : []),
    ...(data.impactComplete === false
      ? ["Impact analysis is incomplete for this scan."]
      : []),
    ...(data.unreadableResourceTypes.length > 0
      ? [
          `Unreadable resource types: ${data.unreadableResourceTypes.join(", ")}.`,
        ]
      : []),
    ...data.warnings,
  ];
}

export function getUsageServices(usage: KubernetesUsage): string[] {
  return uniqueValues(usage.backendServices.map(formatService));
}

export function getUsageWorkloads(usage: KubernetesUsage): string[] {
  return uniqueValues(usage.affectedWorkloads.map(formatWorkload));
}
