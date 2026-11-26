// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  awsApiGatewayCredentialConfigSchema,
  isAwsApiGatewayKvPathRequired,
  isAwsApiGatewayProvider,
  type AwsApiGwAuthMode,
} from "@/lib/credential-config-schemas/aws-api-gateway";
import type {
  CredentialFormValidationValues,
  SchemaRefinementContext,
} from "@/lib/cert-manager/credential-form-schemas/types";

export function isAwsApiGatewayCredentialProvider(provider?: string): boolean {
  return isAwsApiGatewayProvider(provider);
}

export function isAwsApiGatewayCredentialKvPathRequired(
  values: CredentialFormValidationValues,
): boolean {
  const authMode = (values.awsApiGwAuthMode ||
    "STATIC_KEYS") as AwsApiGwAuthMode;
  return isAwsApiGatewayKvPathRequired(authMode);
}

function parseCustomDomains(customDomains?: string[]): string[] {
  return (customDomains || [])
    .map((domain) => domain.trim())
    .filter((domain) => domain.length > 0);
}

export function validateAwsApiGatewayCredentialFields(
  values: CredentialFormValidationValues,
  context: SchemaRefinementContext,
): void {
  const authMode = (values.awsApiGwAuthMode ||
    "STATIC_KEYS") as AwsApiGwAuthMode;
  const result = awsApiGatewayCredentialConfigSchema.safeParse({
    authMode,
    region: values.awsApiGwRegion,
    roleArn: values.awsApiGwRoleArn,
    externalId: values.awsApiGwExternalId,
    customDomains: parseCustomDomains(values.awsApiGwCustomDomains),
  });

  if (!result.success) {
    for (const issue of result.error.issues) {
      if (issue.path[0] === "region") {
        context.addIssue({
          code: "custom",
          path: ["awsApiGwRegion"],
          message: issue.message,
        });
      } else if (issue.path[0] === "roleArn") {
        context.addIssue({
          code: "custom",
          path: ["awsApiGwRoleArn"],
          message: issue.message,
        });
      } else if (issue.path[0] === "customDomains") {
        context.addIssue({
          code: "custom",
          path: ["awsApiGwCustomDomains"],
          message: issue.message,
        });
      }
    }
  }
}
