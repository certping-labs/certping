// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";

import type { IncidentEscalationDraft } from "@/components/incidents/escalate-incident-dialog";
import { Badge, type BadgeProps } from "@/components/ui/badge";
import type { SystemAlert } from "@/hooks/incidents";
import { humanizeEnum } from "@/lib/humanize";
import { formatDateTime } from "@/lib/utils";
import type { UserDto } from "@/types/auth";
import type { IncidentHistoryItem } from "@/types/integrations";

export const NO_ESCALATIONS: IncidentHistoryItem[] = [];

export const formatIncidentDateTime = (value: string | null | undefined) => {
  const formatted = formatDateTime(value ?? null);
  return formatted === "-" ? "N/A" : formatted;
};

export const getAlertTarget = (alert: SystemAlert) =>
  alert.domain || alert.deploymentTarget || "No domain";

export const getAlertMessage = (alert: SystemAlert) =>
  alert.message || "No message available";

export const getProviderLabel = (provider: IncidentHistoryItem["provider"]) =>
  provider === "SERVICENOW_ITSM"
    ? "ServiceNow"
    : provider === "PAGERDUTY"
      ? "PagerDuty"
      : provider;

export const getEscalationReference = (incident: IncidentHistoryItem) =>
  incident.externalReference || incident.externalIncidentId || "-";

const SEVERITY_VARIANT: Record<string, BadgeProps["variant"]> = {
  CRITICAL: "destructive",
  WARNING: "warning",
};

export function SeverityBadge({
  severity,
}: {
  severity: SystemAlert["severity"];
}) {
  return (
    <Badge variant={SEVERITY_VARIANT[severity] ?? "secondary"} textOnly>
      {humanizeEnum(severity)}
    </Badge>
  );
}

export function EmptyCell({ label }: { label: string }) {
  return (
    <span className="text-muted-foreground">
      <span aria-hidden="true">-</span>
      <span className="sr-only">{label}</span>
    </span>
  );
}

export function indexUserEmails(users: readonly UserDto[] | undefined) {
  const emails = new Map<string, string>();
  for (const user of users ?? []) {
    if (user?.id && user.email) emails.set(String(user.id), user.email);
  }
  return emails;
}

export function escalationActor(
  incident: IncidentHistoryItem,
  emails: ReadonlyMap<string, string>,
): string {
  if (incident.source === "INTERNAL_API") return "System";
  if (incident.source === "PUBLIC_API" && incident.actorUserId != null) {
    return emails.get(String(incident.actorUserId)) ?? "-";
  }
  return "-";
}

export function buildEscalationDraft(
  alert: SystemAlert | null,
): IncidentEscalationDraft {
  if (!alert) {
    return {
      alertId: 0,
      title: "",
      description: "",
      severity: "INFO",
      source: "certping/incidents-alerts",
    };
  }
  return {
    alertId: Number.parseInt(alert.id, 10),
    title: `Alert failure: ${alert.domain || alert.deploymentTarget || alert.id}`,
    description: [
      `Source: ${alert.source.toUpperCase()}`,
      alert.domain ? `Domain: ${alert.domain}` : "",
      alert.deploymentTarget
        ? `Deployment target: ${alert.deploymentTarget}`
        : "",
      alert.status ? `Status: ${alert.status}` : "",
      alert.message ? `Message: ${alert.message}` : "",
    ]
      .filter(Boolean)
      .join("\n"),
    severity:
      alert.severity === "CRITICAL" || alert.severity === "WARNING"
        ? alert.severity
        : "INFO",
    source: "certping/incidents-alerts",
    dedupKey: `alert:${alert.source}:${alert.id}`,
  };
}
