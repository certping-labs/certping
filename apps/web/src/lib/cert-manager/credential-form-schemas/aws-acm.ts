// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  awsAcmCredentialConfigSchema,
  isAwsAcmKvPathRequired,
  isAwsAcmProvider,
  type AwsAcmAuthMode,
} from "@/lib/credential-config-schemas/aws-acm";
import type {
  CredentialFormValidationValues,
  SchemaRefinementContext,
} from "@/lib/cert-manager/credential-form-schemas/types";

export function isAwsAcmCredentialProvider(provider?: string): boolean {
  return isAwsAcmProvider(provider);
}

export function isAwsAcmCredentialKvPathRequired(
  values: CredentialFormValidationValues,
): boolean {
  const authMode = (values.awsAcmAuthMode || "STATIC_KEYS") as AwsAcmAuthMode;
  return isAwsAcmKvPathRequired(authMode);
}

export function validateAwsAcmCredentialFields(
  values: CredentialFormValidationValues,
  context: SchemaRefinementContext,
): void {
  const authMode = (values.awsAcmAuthMode || "STATIC_KEYS") as AwsAcmAuthMode;
  const result = awsAcmCredentialConfigSchema.safeParse({
    authMode,
    region: values.awsAcmRegion,
    roleArn: values.awsAcmRoleArn,
    externalId: values.awsAcmExternalId,
  });

  if (!result.success) {
    for (const issue of result.error.issues) {
      if (issue.path[0] === "region") {
        context.addIssue({
          code: "custom",
          path: ["awsAcmRegion"],
          message: issue.message,
        });
      } else if (issue.path[0] === "roleArn") {
        context.addIssue({
          code: "custom",
          path: ["awsAcmRoleArn"],
          message: issue.message,
        });
      }
    }
  }
}
