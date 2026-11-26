// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

export const cloudflareEdgeCredentialConfigSchema = z.object({
  zoneId: z.string().trim().min(1, "Zone ID is required"),
});

export type CloudflareEdgeCredentialConfig = z.infer<
  typeof cloudflareEdgeCredentialConfigSchema
>;

export function parseCloudflareEdgeCredentialConfig(
  configJson?: unknown,
): CloudflareEdgeCredentialConfig | null {
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
    const result = cloudflareEdgeCredentialConfigSchema.safeParse(normalized);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

export function isCloudflareEdgeProvider(value?: string): boolean {
  return (value || "").trim().toUpperCase() === "CLOUDFLARE_EDGE";
}
