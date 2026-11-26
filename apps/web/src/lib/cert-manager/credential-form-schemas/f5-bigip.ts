// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  f5BigipCredentialConfigSchema,
  isF5BigipProvider,
} from "@/lib/credential-config-schemas/f5-bigip";
import type {
  CredentialFormValidationValues,
  SchemaRefinementContext,
} from "@/lib/cert-manager/credential-form-schemas/types";

export function isF5BigipCredentialProvider(provider?: string): boolean {
  return isF5BigipProvider(provider);
}

export function isF5BigipCredentialKvPathRequired(): boolean {
  return true;
}

export function validateF5BigipCredentialFields(
  values: CredentialFormValidationValues,
  context: SchemaRefinementContext,
): void {
  const result = f5BigipCredentialConfigSchema.safeParse({
    bigipHost: values.f5BigipHost,
    partition: values.f5BigipPartition,
    clientSslProfiles: values.f5BigipClientSslProfiles || [],
  });

  if (result.success) {
    return;
  }

  const fieldMap: Record<string, keyof CredentialFormValidationValues> = {
    bigipHost: "f5BigipHost",
    partition: "f5BigipPartition",
    clientSslProfiles: "f5BigipClientSslProfiles",
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
