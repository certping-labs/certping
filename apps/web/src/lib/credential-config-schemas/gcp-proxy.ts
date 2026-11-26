// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

import {
  gcpScopeBaseSchema,
  isGcpKvPathRequired,
  type GcpAuthMode,
} from "@/lib/credential-config-schemas/gcp-shared";

export const gcpProxyCredentialConfigSchema = gcpScopeBaseSchema
  .extend({
    targetProxy: z.string().trim().optional(),
    targetSslProxy: z.string().trim().optional(),
  })
  .superRefine((value, ctx) => {
    const proxy = (value.targetProxy || "").trim();
    const sslProxy = (value.targetSslProxy || "").trim();
    if (!proxy && !sslProxy) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["targetProxy"],
        message: "Target proxy is required",
      });
    }
  });

export type GcpProxyCredentialConfig = z.infer<
  typeof gcpProxyCredentialConfigSchema
>;

export function parseGcpProxyCredentialConfig(
  configJson?: unknown,
): GcpProxyCredentialConfig | null {
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
    const result = gcpProxyCredentialConfigSchema.safeParse(normalized);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

export function isGcpProxyProvider(value?: string): boolean {
  const normalized = (value || "").trim().toUpperCase();
  return (
    normalized === "GCP_ALB" ||
    normalized === "GCP_API_GW" ||
    normalized === "GCP_CLOUD_CDN" ||
    normalized === "GCP_PROXY_NLB"
  );
}

export function isGcpProxyKvPathRequired(mode: GcpAuthMode): boolean {
  return isGcpKvPathRequired(mode);
}
