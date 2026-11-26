// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

export const GCP_AUTH_MODES = [
  "SERVICE_ACCOUNT_KEY",
  "WORKLOAD_IDENTITY",
  "IMPERSONATE_SERVICE_ACCOUNT",
] as const;

export type GcpAuthMode = (typeof GCP_AUTH_MODES)[number];

export const gcpScopeBaseSchema = z.object({
  authMode: z.enum(GCP_AUTH_MODES),
  projectId: z.string().trim().min(1, "Project ID is required"),
  location: z.string().trim().min(1, "Location is required"),
  impersonateServiceAccount: z.string().trim().optional(),
});

const AUTH_MODE_LABELS: Record<GcpAuthMode, string> = {
  SERVICE_ACCOUNT_KEY: "Service account key",
  WORKLOAD_IDENTITY: "Workload identity / ADC",
  IMPERSONATE_SERVICE_ACCOUNT: "Impersonate service account",
};

const AUTH_MODE_HELP: Record<GcpAuthMode, string> = {
  SERVICE_ACCOUNT_KEY:
    "Store a GCP service account key JSON in your secret manager and reference it via a secret handle.",
  WORKLOAD_IDENTITY:
    "No secret handle required. The agent uses Application Default Credentials (GKE Workload Identity / metadata server).",
  IMPERSONATE_SERVICE_ACCOUNT:
    "No secret handle required. The agent uses ADC and then impersonates the given service account.",
};

const AUTH_MODE_SECRET_TEMPLATES: Record<GcpAuthMode, string> = {
  SERVICE_ACCOUNT_KEY: JSON.stringify(
    {
      serviceAccountKeyJson: {
        type: "service_account",
        project_id: "my-gcp-project-123",
        private_key_id: "<private-key-id>",
        private_key:
          "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
        client_email:
          "certping-rotator@my-gcp-project-123.iam.gserviceaccount.com",
        client_id: "<client-id>",
        auth_uri: "https://accounts.google.com/o/oauth2/auth",
        token_uri: "https://oauth2.googleapis.com/token",
        auth_provider_x509_cert_url:
          "https://www.googleapis.com/oauth2/v1/certs",
        client_x509_cert_url:
          "https://www.googleapis.com/robot/v1/metadata/x509/<service-account-email>",
        universe_domain: "googleapis.com",
      },
    },
    null,
    2,
  ),
  WORKLOAD_IDENTITY: JSON.stringify(
    { note: "No secret handle required for workload identity / ADC" },
    null,
    2,
  ),
  IMPERSONATE_SERVICE_ACCOUNT: JSON.stringify(
    {
      note: "No secret handle required when using service account impersonation",
    },
    null,
    2,
  ),
};

export function getGcpAuthModeLabel(mode: GcpAuthMode): string {
  return AUTH_MODE_LABELS[mode];
}

export function getGcpAuthModeHelp(mode: GcpAuthMode): string {
  return AUTH_MODE_HELP[mode];
}

export function getGcpAuthModeSecretTemplate(mode: GcpAuthMode): string {
  return AUTH_MODE_SECRET_TEMPLATES[mode];
}

export function isGcpKvPathRequired(mode: GcpAuthMode): boolean {
  return mode === "SERVICE_ACCOUNT_KEY";
}
