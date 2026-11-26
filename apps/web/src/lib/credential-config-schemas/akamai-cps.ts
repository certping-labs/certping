// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

export const akamaiCpsCredentialConfigSchema = z.object({
  host: z.string().trim().min(1, "Host is required"),
  enrollmentId: z.string().trim().min(1, "Enrollment ID is required"),
});

export type AkamaiCpsCredentialConfig = z.infer<
  typeof akamaiCpsCredentialConfigSchema
>;

export function parseAkamaiCpsCredentialConfig(
  configJson?: unknown,
): AkamaiCpsCredentialConfig | null {
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
    const result = akamaiCpsCredentialConfigSchema.safeParse(normalized);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

export function isAkamaiCpsProvider(value?: string): boolean {
  return (value || "").trim().toUpperCase() === "AKAMAI_CPS";
}

export function isAkamaiCpsKvPathRequired(): boolean {
  return true;
}

export function getAkamaiCpsSecretTemplate(): string {
  return JSON.stringify(
    {
      clientToken: "akab-...",
      accessToken: "akab-...",
      clientSecret: "CLIENT_SECRET",
    },
    null,
    2,
  );
}
