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

export const AWS_LOAD_BALANCER_AUTH_MODES = AWS_ACM_AUTH_MODES;
export type AwsLoadBalancerAuthMode = AwsAcmAuthMode;

const regionSchema = z.string().trim().min(1, "Region is required");
const roleArnSchema = z.string().trim().min(1, "Role ARN is required");
const listenerArnSchema = z
  .string()
  .trim()
  .min(1, "Listener value is required");

export const awsLoadBalancerCredentialConfigSchema = z
  .object({
    authMode: z.enum(AWS_LOAD_BALANCER_AUTH_MODES),
    region: regionSchema,
    roleArn: z.string().trim().optional(),
    externalId: z.string().trim().optional(),
    listeners: z
      .array(listenerArnSchema)
      .min(1, "At least one listener ARN is required"),
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

export type AwsLoadBalancerCredentialConfig = z.infer<
  typeof awsLoadBalancerCredentialConfigSchema
>;

export function parseAwsLoadBalancerCredentialConfig(
  configJson?: unknown,
): AwsLoadBalancerCredentialConfig | null {
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
    const result = awsLoadBalancerCredentialConfigSchema.safeParse(normalized);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

export function isAwsAlbProvider(value?: string): boolean {
  return (value || "").trim().toUpperCase() === "AWS_ALB";
}

export function isAwsNlbProvider(value?: string): boolean {
  return (value || "").trim().toUpperCase() === "AWS_NLB";
}

export function isAwsLoadBalancerProvider(value?: string): boolean {
  return isAwsAlbProvider(value) || isAwsNlbProvider(value);
}

export function isAwsLoadBalancerKvPathRequired(
  mode: AwsLoadBalancerAuthMode,
): boolean {
  return mode === "STATIC_KEYS";
}

export function getAwsLoadBalancerAuthModeLabel(
  mode: AwsLoadBalancerAuthMode,
): string {
  return getAwsAcmAuthModeLabel(mode);
}

export function getAwsLoadBalancerAuthModeHelp(
  mode: AwsLoadBalancerAuthMode,
): string {
  return getAwsAcmAuthModeHelp(mode);
}

export function getAwsLoadBalancerAuthModeSecretTemplate(
  mode: AwsLoadBalancerAuthMode,
): string {
  return getAwsAcmAuthModeSecretTemplate(mode);
}
