// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  akamaiCpsCredentialConfigSchema,
  isAkamaiCpsProvider,
} from "@/lib/credential-config-schemas/akamai-cps";
import type {
  CredentialFormValidationValues,
  SchemaRefinementContext,
} from "@/lib/cert-manager/credential-form-schemas/types";

export function isAkamaiCpsCredentialProvider(provider?: string): boolean {
  return isAkamaiCpsProvider(provider);
}

export function isAkamaiCpsCredentialKvPathRequired(): boolean {
  return true;
}

export function validateAkamaiCpsCredentialFields(
  values: CredentialFormValidationValues,
  context: SchemaRefinementContext,
): void {
  const result = akamaiCpsCredentialConfigSchema.safeParse({
    host: values.akamaiHost,
    enrollmentId: values.akamaiEnrollmentId,
  });

  if (result.success) {
    return;
  }

  const fieldMap: Record<string, keyof CredentialFormValidationValues> = {
    host: "akamaiHost",
    enrollmentId: "akamaiEnrollmentId",
  };

  for (const issue of result.error.issues) {
    const key = String(issue.path[0] || "");
    const mapped = fieldMap[key];
    if (mapped) {
      context.addIssue({
        code: "custom",
        path: [mapped],
        message: issue.message,
      });
    }
  }
}
