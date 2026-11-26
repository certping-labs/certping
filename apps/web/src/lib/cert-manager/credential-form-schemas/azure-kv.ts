// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  azureKvCredentialConfigSchema,
  isAzureKvKvPathRequired,
  isAzureKvProvider,
  type AzureKvAuthMode,
} from "@/lib/credential-config-schemas/azure-kv";
import type {
  CredentialFormValidationValues,
  SchemaRefinementContext,
} from "@/lib/cert-manager/credential-form-schemas/types";

export function isAzureKvCredentialProvider(provider?: string): boolean {
  return isAzureKvProvider(provider);
}

export function isAzureKvCredentialKvPathRequired(
  values: CredentialFormValidationValues,
): boolean {
  const authMode = (values.azureKvAuthMode ||
    "SERVICE_PRINCIPAL") as AzureKvAuthMode;
  return isAzureKvKvPathRequired(authMode);
}

export function validateAzureKvCredentialFields(
  values: CredentialFormValidationValues,
  context: SchemaRefinementContext,
): void {
  const authMode = (values.azureKvAuthMode ||
    "SERVICE_PRINCIPAL") as AzureKvAuthMode;
  const result = azureKvCredentialConfigSchema.safeParse({
    authMode,
    tenantId: values.azureKvTenantId,
    vaultUri: values.azureKvVaultUri,
  });

  if (authMode === "WORKLOAD_IDENTITY" && !values.azureKvClientId?.trim()) {
    context.addIssue({
      code: "custom",
      path: ["azureKvClientId"],
      message: "Client ID is required for workload identity",
    });
  }

  if (!result.success) {
    for (const issue of result.error.issues) {
      if (issue.path[0] === "vaultUri") {
        context.addIssue({
          code: "custom",
          path: ["azureKvVaultUri"],
          message: issue.message,
        });
      } else if (issue.path[0] === "tenantId") {
        context.addIssue({
          code: "custom",
          path: ["azureKvTenantId"],
          message: issue.message,
        });
      }
    }
  }
}
