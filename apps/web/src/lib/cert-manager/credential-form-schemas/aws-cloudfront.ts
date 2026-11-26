// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  awsCloudFrontCredentialConfigSchema,
  isAwsCloudFrontKvPathRequired,
  isAwsCloudFrontProvider,
  type AwsCloudFrontAuthMode,
} from "@/lib/credential-config-schemas/aws-cloudfront";
import type {
  CredentialFormValidationValues,
  SchemaRefinementContext,
} from "@/lib/cert-manager/credential-form-schemas/types";

export function isAwsCloudFrontCredentialProvider(provider?: string): boolean {
  return isAwsCloudFrontProvider(provider);
}

export function isAwsCloudFrontCredentialKvPathRequired(
  values: CredentialFormValidationValues,
): boolean {
  const authMode = (values.awsCloudFrontAuthMode ||
    "STATIC_KEYS") as AwsCloudFrontAuthMode;
  return isAwsCloudFrontKvPathRequired(authMode);
}

export function validateAwsCloudFrontCredentialFields(
  values: CredentialFormValidationValues,
  context: SchemaRefinementContext,
): void {
  const authMode = (values.awsCloudFrontAuthMode ||
    "STATIC_KEYS") as AwsCloudFrontAuthMode;
  const result = awsCloudFrontCredentialConfigSchema.safeParse({
    authMode,
    distributionId: values.awsCloudFrontDistributionId,
    roleArn: values.awsCloudFrontRoleArn,
    externalId: values.awsCloudFrontExternalId,
  });

  if (!result.success) {
    for (const issue of result.error.issues) {
      if (issue.path[0] === "distributionId") {
        context.addIssue({
          code: "custom",
          path: ["awsCloudFrontDistributionId"],
          message: issue.message,
        });
      } else if (issue.path[0] === "roleArn") {
        context.addIssue({
          code: "custom",
          path: ["awsCloudFrontRoleArn"],
          message: issue.message,
        });
      }
    }
  }
}
