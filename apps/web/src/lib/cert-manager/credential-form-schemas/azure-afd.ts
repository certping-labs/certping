// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  azureAfdCredentialConfigSchema,
  isAzureAfdKvPathRequired,
  isAzureAfdProvider,
  type AzureAfdAuthMode,
} from "@/lib/credential-config-schemas/azure-afd";
import type {
  CredentialFormValidationValues,
  SchemaRefinementContext,
} from "@/lib/cert-manager/credential-form-schemas/types";

export function isAzureAfdCredentialProvider(provider?: string): boolean {
  return isAzureAfdProvider(provider);
}

export function isAzureAfdCredentialKvPathRequired(
  values: CredentialFormValidationValues,
): boolean {
  const authMode = (values.azureAfdAuthMode ||
    "SERVICE_PRINCIPAL") as AzureAfdAuthMode;
  return isAzureAfdKvPathRequired(authMode);
}

export function validateAzureAfdCredentialFields(
  values: CredentialFormValidationValues,
  context: SchemaRefinementContext,
): void {
  const customDomains = (values.azureAfdCustomDomains || [])
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
  const authMode = (values.azureAfdAuthMode ||
    "SERVICE_PRINCIPAL") as AzureAfdAuthMode;
  if (authMode === "WORKLOAD_IDENTITY" && !values.azureAfdClientId?.trim()) {
    context.addIssue({
      code: "custom",
      path: ["azureAfdClientId"],
      message: "Client ID is required for workload identity",
    });
  }
  const result = azureAfdCredentialConfigSchema.safeParse({
    authMode,
    tenantId: values.azureAfdTenantId,
    subscriptionId: values.azureAfdSubscriptionId,
    clientId: values.azureAfdClientId?.trim() || undefined,
    resourceGroup: values.azureAfdResourceGroup,
    profileName: values.azureAfdProfileName,
    keyVaultUri: values.azureAfdKeyVaultUri,
    customDomains,
  });

  if (!result.success) {
    for (const issue of result.error.issues) {
      const field = issue.path[0];
      if (typeof field !== "string") {
        continue;
      }
      const map: Record<string, keyof CredentialFormValidationValues> = {
        tenantId: "azureAfdTenantId",
        subscriptionId: "azureAfdSubscriptionId",
        clientId: "azureAfdClientId",
        resourceGroup: "azureAfdResourceGroup",
        profileName: "azureAfdProfileName",
        keyVaultUri: "azureAfdKeyVaultUri",
        customDomains: "azureAfdCustomDomains",
      };
      const target = map[field];
      if (!target) {
        continue;
      }
      context.addIssue({
        code: "custom",
        path: [target],
        message: issue.message,
      });
    }
  }
}
