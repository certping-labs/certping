// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

export const AWS_ACM_AUTH_MODES = [
  "STATIC_KEYS",
  "ASSUME_ROLE",
  "INSTANCE_PROFILE",
] as const;

export type AwsAcmAuthMode = (typeof AWS_ACM_AUTH_MODES)[number];

const regionSchema = z.string().trim().min(1, "Region is required");
const roleArnSchema = z.string().trim().min(1, "Role ARN is required");

export const awsAcmCredentialConfigSchema = z
  .object({
    authMode: z.enum(AWS_ACM_AUTH_MODES),
    region: regionSchema,
    roleArn: z.string().trim().optional(),
    externalId: z.string().trim().optional(),
  })
  .superRefine((value, ctx) => {
    if (value.authMode === "ASSUME_ROLE") {
      const roleArn = (value.roleArn || "").trim();
      if (!roleArnSchema.safeParse(roleArn).success) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["roleArn"],
          message: "Role ARN is required for assume-role auth",
        });
      }
    }
  });

export type AwsAcmCredentialConfig = z.infer<
  typeof awsAcmCredentialConfigSchema
>;

const AUTH_MODE_LABELS: Record<AwsAcmAuthMode, string> = {
  STATIC_KEYS: "Static access keys",
  ASSUME_ROLE: "Assume role",
  INSTANCE_PROFILE: "Instance profile / workload identity",
};

const AUTH_MODE_HELP: Record<AwsAcmAuthMode, string> = {
  STATIC_KEYS:
    "Store AWS access keys in your secret manager and reference them via a secret handle.",
  ASSUME_ROLE:
    "Use the agent runtime AWS identity to assume the role ARN at runtime (optionally with an external ID).",
  INSTANCE_PROFILE:
    "No secret handle required. The agent uses its runtime identity (EC2/ECS/EKS IRSA) to call AWS APIs.",
};

const AUTH_MODE_SECRET_TEMPLATES: Record<AwsAcmAuthMode, string> = {
  STATIC_KEYS: JSON.stringify(
    {
      accessKeyId: "ACCESS_KEY_ID",
      secretAccessKey: "SECRET_ACCESS_KEY",
    },
    null,
    2,
  ),
  ASSUME_ROLE: JSON.stringify(
    {
      note: "No secret handle required for assume-role auth",
    },
    null,
    2,
  ),
  INSTANCE_PROFILE: JSON.stringify(
    {
      note: "No secret handle required for instance profile / workload identity",
    },
    null,
    2,
  ),
};

export function parseAwsAcmCredentialConfig(
  configJson?: unknown,
): AwsAcmCredentialConfig | null {
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
    const result = awsAcmCredentialConfigSchema.safeParse(normalized);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

export function getAwsAcmAuthModeLabel(mode: AwsAcmAuthMode): string {
  return AUTH_MODE_LABELS[mode];
}

export function getAwsAcmAuthModeHelp(mode: AwsAcmAuthMode): string {
  return AUTH_MODE_HELP[mode];
}

export function getAwsAcmAuthModeSecretTemplate(mode: AwsAcmAuthMode): string {
  return AUTH_MODE_SECRET_TEMPLATES[mode];
}

export function isAwsAcmProvider(value?: string): boolean {
  return (value || "").trim().toUpperCase() === "AWS_ACM";
}

export function isAwsAcmKvPathRequired(mode: AwsAcmAuthMode): boolean {
  return mode === "STATIC_KEYS";
}
