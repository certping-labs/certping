// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

export type IntegrationProvider =
  "SLACK" | "TEAMS" | "PAGERDUTY" | "SERVICENOW_ITSM";

export type IntegrationStatus = "ACTIVE" | "DISABLED";

export interface Integration {
  id: number;
  provider: IntegrationProvider;
  status: IntegrationStatus;
  createdAt: string | null;
  updatedAt: string | null;
  deletedAt: string | null;
}

export interface SlackTeamsIntegrationPayload {
  provider: "SLACK" | "TEAMS";
  webhookUrl: string;
}

export interface PagerDutyIntegrationPayload {
  provider: "PAGERDUTY";
  routingKey: string;
}

export interface ServiceNowIntegrationPayload {
  provider: "SERVICENOW_ITSM";
  instanceUrl: string;
  clientId: string;
  clientSecret: string;
  oauthScope?: string;
}

export type CreateIntegrationPayload =
  | SlackTeamsIntegrationPayload
  | PagerDutyIntegrationPayload
  | ServiceNowIntegrationPayload;

export type UpdateIntegrationPayload = Omit<
  CreateIntegrationPayload,
  "provider"
>;

export type PagerDutySeverity = "CRITICAL" | "ERROR" | "WARNING" | "INFO";

export interface PagerDutyIncidentLink {
  href: string;
  text: string;
}

export interface CreatePagerDutyIncidentPayload {
  alertId: number;
  title: string;
  source: string;
  severity: PagerDutySeverity;
  dedupKey?: string;
  component?: string;
  group?: string;
  className?: string;
  customDetails?: Record<string, unknown>;
  links?: PagerDutyIncidentLink[];
}

export interface CreatePagerDutyIncidentResponse {
  status?: string;
  message?: string;
  dedupKey?: string;
}

export type ServiceNowPriority = "HIGH" | "MEDIUM" | "LOW";

export interface CreateServiceNowIncidentPayload {
  alertId: number;
  shortDescription: string;
  description?: string;
  impact?: ServiceNowPriority;
  urgency?: ServiceNowPriority;
  category?: string;
  subcategory?: string;
  assignmentGroup?: string;
  businessService?: string;
  configurationItem?: string;
  callerId?: string;
  correlationId?: string;
  correlationDisplay?: string;
  comments?: string;
  workNotes?: string;
}

export interface CreateServiceNowIncidentResponse {
  sysId?: string;
  number?: string;
  recordUrl?: string;
  displayUrl?: string;
}

export type IncidentHistorySource = "PUBLIC_API" | "INTERNAL_API";

export interface IncidentHistoryItem {
  id: number;
  provider: IntegrationProvider;
  source: IncidentHistorySource | null;
  actorUserId: number | null;
  alertId: number | null;
  summary: string | null;
  externalIncidentId: string | null;
  externalReference: string | null;
  externalUrl: string | null;
  createdAt: string | null;
}

export interface IncidentHistoryPage {
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
  items: IncidentHistoryItem[];
}
