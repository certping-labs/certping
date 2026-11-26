// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

import {
  gcpScopeBaseSchema,
  isGcpKvPathRequired,
  type GcpAuthMode,
} from "@/lib/credential-config-schemas/gcp-shared";

export const gcpCertManagerCredentialConfigSchema = gcpScopeBaseSchema.extend({
  certificateMap: z.string().trim().optional(),
});

export type GcpCertManagerCredentialConfig = z.infer<
  typeof gcpCertManagerCredentialConfigSchema
>;

export function parseGcpCertManagerCredentialConfig(
  configJson?: unknown,
): GcpCertManagerCredentialConfig | null {
  if (!configJson) {
    return null;
  }

  try {
    const parsed =
      typeof configJson === "string"
        ? (JSON.parse(configJson) as unknown)
        : configJson;
    const normalized =
      parsed && typeof parsed === "object" && "config" in parsed
        ? (parsed as { config?: unknown }).config
        : parsed;
    const result = gcpCertManagerCredentialConfigSchema.safeParse(normalized);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

export function isGcpCertManagerProvider(value?: string): boolean {
  return (value || "").trim().toUpperCase() === "GCP_CERT_MANAGER";
}

export function isGcpCertManagerKvPathRequired(mode: GcpAuthMode): boolean {
  return isGcpKvPathRequired(mode);
}
