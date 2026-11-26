// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  awsLoadBalancerCredentialConfigSchema,
  isAwsLoadBalancerKvPathRequired,
  isAwsLoadBalancerProvider,
  type AwsLoadBalancerAuthMode,
} from "@/lib/credential-config-schemas/aws-load-balancer";
import type {
  CredentialFormValidationValues,
  SchemaRefinementContext,
} from "@/lib/cert-manager/credential-form-schemas/types";

export function isAwsLoadBalancerCredentialProvider(
  provider?: string,
): boolean {
  return isAwsLoadBalancerProvider(provider);
}

export function isAwsLoadBalancerCredentialKvPathRequired(
  values: CredentialFormValidationValues,
): boolean {
  const authMode = (values.awsElbAuthMode ||
    "STATIC_KEYS") as AwsLoadBalancerAuthMode;
  return isAwsLoadBalancerKvPathRequired(authMode);
}

function parseListeners(listeners?: string[]): string[] {
  return (listeners || [])
    .map((listener) => listener.trim())
    .filter((listener) => listener.length > 0);
}

export function validateAwsLoadBalancerCredentialFields(
  values: CredentialFormValidationValues,
  context: SchemaRefinementContext,
): void {
  const authMode = (values.awsElbAuthMode ||
    "STATIC_KEYS") as AwsLoadBalancerAuthMode;
  const result = awsLoadBalancerCredentialConfigSchema.safeParse({
    authMode,
    region: values.awsElbRegion,
    roleArn: values.awsElbRoleArn,
    externalId: values.awsElbExternalId,
    listeners: parseListeners(values.awsElbListeners),
  });

  if (!result.success) {
    for (const issue of result.error.issues) {
      if (issue.path[0] === "region") {
        context.addIssue({
          code: "custom",
          path: ["awsElbRegion"],
          message: issue.message,
        });
      } else if (issue.path[0] === "roleArn") {
        context.addIssue({
          code: "custom",
          path: ["awsElbRoleArn"],
          message: issue.message,
        });
      } else if (issue.path[0] === "listeners") {
        context.addIssue({
          code: "custom",
          path: ["awsElbListeners"],
          message: issue.message,
        });
      }
    }
  }
}
