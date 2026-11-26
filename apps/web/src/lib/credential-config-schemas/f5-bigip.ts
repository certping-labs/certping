// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

export function normalizeF5BigipHost(input: string): string {
  const raw = (input || "").trim();
  if (!raw) {
    return "";
  }

  // Accept either a plain hostname/IP (recommended) or a full URL pasted from a browser.
  // The agent contract expects just the host (no scheme/path).
  if (/^https?:\/\//i.test(raw)) {
    try {
      return new URL(raw).hostname;
    } catch {
      // Fall through to manual normalization.
    }
  }

  return raw
    .replace(/\/+$/, "")
    .replace(/^https?:\/\//i, "")
    .split("/")[0];
}

export const f5BigipCredentialConfigSchema = z.object({
  bigipHost: z
    .string()
    .trim()
    .min(1, "BIG-IP host is required")
    .transform((value) => normalizeF5BigipHost(value)),
  partition: z.string().trim().min(1, "Partition is required"),
  clientSslProfiles: z
    .array(z.string().trim())
    .optional()
    .default(["clientssl-api"]),
});

export type F5BigipCredentialConfig = z.infer<
  typeof f5BigipCredentialConfigSchema
>;

export function parseF5BigipCredentialConfig(
  configJson?: unknown,
): F5BigipCredentialConfig | null {
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
    const result = f5BigipCredentialConfigSchema.safeParse(normalized);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

export function isF5BigipProvider(value?: string): boolean {
  return (value || "").trim().toUpperCase() === "F5_BIGIP";
}

export function isF5BigipKvPathRequired(): boolean {
  return true;
}

export function getF5BigipSecretTemplate(): string {
  return JSON.stringify({ username: "admin", password: "PASSWORD" }, null, 2);
}
