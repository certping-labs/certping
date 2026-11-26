// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

import { AWS_ACM_AUTH_MODES } from "@/lib/credential-config-schemas/aws-acm";

export const AWS_CLOUDFRONT_AUTH_MODES = AWS_ACM_AUTH_MODES;
export type AwsCloudFrontAuthMode = (typeof AWS_CLOUDFRONT_AUTH_MODES)[number];

const distributionIdSchema = z
  .string()
  .trim()
  .min(1, "Distribution ID is required");
const roleArnSchema = z.string().trim().min(1, "Role ARN is required");

export const awsCloudFrontCredentialConfigSchema = z
  .object({
    authMode: z.enum(AWS_CLOUDFRONT_AUTH_MODES),
    distributionId: distributionIdSchema,
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

export type AwsCloudFrontCredentialConfig = z.infer<
  typeof awsCloudFrontCredentialConfigSchema
>;

const AUTH_MODE_LABELS: Record<AwsCloudFrontAuthMode, string> = {
  STATIC_KEYS: "Static access keys",
  ASSUME_ROLE: "Assume role",
  INSTANCE_PROFILE: "Instance profile / workload identity",
};

const AUTH_MODE_HELP: Record<AwsCloudFrontAuthMode, string> = {
  STATIC_KEYS:
    "Store AWS access keys in your secret manager and reference them via a secret handle.",
  ASSUME_ROLE:
    "Assume the role ARN at runtime (optionally with an external ID). Secret handle is optional if the agent already has AWS credentials via runtime identity.",
  INSTANCE_PROFILE:
    "No secret handle required. The agent uses its runtime identity (EC2/ECS/EKS IRSA) to call AWS APIs.",
};

const AUTH_MODE_SECRET_TEMPLATES: Record<AwsCloudFrontAuthMode, string> = {
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

export function parseAwsCloudFrontCredentialConfig(
  configJson?: unknown,
): AwsCloudFrontCredentialConfig | null {
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
    const result = awsCloudFrontCredentialConfigSchema.safeParse(normalized);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

export function getAwsCloudFrontAuthModeLabel(
  mode: AwsCloudFrontAuthMode,
): string {
  return AUTH_MODE_LABELS[mode];
}

export function getAwsCloudFrontAuthModeHelp(
  mode: AwsCloudFrontAuthMode,
): string {
  return AUTH_MODE_HELP[mode];
}

export function getAwsCloudFrontAuthModeSecretTemplate(
  mode: AwsCloudFrontAuthMode,
): string {
  return AUTH_MODE_SECRET_TEMPLATES[mode];
}

export function isAwsCloudFrontProvider(value?: string): boolean {
  return (value || "").trim().toUpperCase() === "AWS_CLOUDFRONT";
}

export function isAwsCloudFrontKvPathRequired(
  mode: AwsCloudFrontAuthMode,
): boolean {
  return mode === "STATIC_KEYS";
}
