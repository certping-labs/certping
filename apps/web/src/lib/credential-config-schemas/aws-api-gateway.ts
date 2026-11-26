// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

import {
  AWS_ACM_AUTH_MODES,
  getAwsAcmAuthModeHelp,
  getAwsAcmAuthModeLabel,
  getAwsAcmAuthModeSecretTemplate,
  type AwsAcmAuthMode,
} from "@/lib/credential-config-schemas/aws-acm";

export const AWS_API_GW_AUTH_MODES = AWS_ACM_AUTH_MODES;
export type AwsApiGwAuthMode = AwsAcmAuthMode;

const regionSchema = z.string().trim().min(1, "Region is required");
const roleArnSchema = z.string().trim().min(1, "Role ARN is required");
const customDomainSchema = z
  .string()
  .trim()
  .min(1, "Custom domain is required");

export const awsApiGatewayCredentialConfigSchema = z
  .object({
    authMode: z.enum(AWS_API_GW_AUTH_MODES),
    region: regionSchema,
    roleArn: z.string().trim().optional(),
    externalId: z.string().trim().optional(),
    customDomains: z
      .array(customDomainSchema)
      .min(1, "At least one custom domain is required"),
  })
  .superRefine((value, context) => {
    if (value.authMode === "ASSUME_ROLE") {
      const roleArn = (value.roleArn || "").trim();
      if (!roleArnSchema.safeParse(roleArn).success) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["roleArn"],
          message: "Role ARN is required for assume-role auth",
        });
      }
    }
  });

export type AwsApiGatewayCredentialConfig = z.infer<
  typeof awsApiGatewayCredentialConfigSchema
>;

export function parseAwsApiGatewayCredentialConfig(
  configJson?: unknown,
): AwsApiGatewayCredentialConfig | null {
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
    const result = awsApiGatewayCredentialConfigSchema.safeParse(normalized);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

export function isAwsApiGatewayRestProvider(value?: string): boolean {
  return (value || "").trim().toUpperCase() === "AWS_API_GW_REST";
}

export function isAwsApiGatewayHttpProvider(value?: string): boolean {
  return (value || "").trim().toUpperCase() === "AWS_API_GW_HTTP";
}

export function isAwsApiGatewayProvider(value?: string): boolean {
  return (
    isAwsApiGatewayRestProvider(value) || isAwsApiGatewayHttpProvider(value)
  );
}

export function isAwsApiGatewayKvPathRequired(mode: AwsApiGwAuthMode): boolean {
  return mode === "STATIC_KEYS";
}

export function getAwsApiGatewayAuthModeLabel(mode: AwsApiGwAuthMode): string {
  return getAwsAcmAuthModeLabel(mode);
}

export function getAwsApiGatewayAuthModeHelp(mode: AwsApiGwAuthMode): string {
  return getAwsAcmAuthModeHelp(mode);
}

export function getAwsApiGatewayAuthModeSecretTemplate(
  mode: AwsApiGwAuthMode,
): string {
  return getAwsAcmAuthModeSecretTemplate(mode);
}
