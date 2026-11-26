// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  azureAppGwCredentialConfigSchema,
  isAzureAppGwKvPathRequired,
  isAzureAppGwProvider,
  type AzureAppGwAuthMode,
} from "@/lib/credential-config-schemas/azure-app-gw";
import type {
  CredentialFormValidationValues,
  SchemaRefinementContext,
} from "@/lib/cert-manager/credential-form-schemas/types";

export function isAzureAppGwCredentialProvider(provider?: string): boolean {
  return isAzureAppGwProvider(provider);
}

export function isAzureAppGwCredentialKvPathRequired(
  values: CredentialFormValidationValues,
): boolean {
  const authMode = (values.azureAppGwAuthMode ||
    "SERVICE_PRINCIPAL") as AzureAppGwAuthMode;
  return isAzureAppGwKvPathRequired(authMode);
}

export function validateAzureAppGwCredentialFields(
  values: CredentialFormValidationValues,
  context: SchemaRefinementContext,
): void {
  const listeners = (values.azureAppGwListeners || [])
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
  const authMode = (values.azureAppGwAuthMode ||
    "SERVICE_PRINCIPAL") as AzureAppGwAuthMode;
  if (authMode === "WORKLOAD_IDENTITY" && !values.azureAppGwClientId?.trim()) {
    context.addIssue({
      code: "custom",
      path: ["azureAppGwClientId"],
      message: "Client ID is required for workload identity",
    });
  }
  const result = azureAppGwCredentialConfigSchema.safeParse({
    authMode,
    tenantId: values.azureAppGwTenantId,
    subscriptionId: values.azureAppGwSubscriptionId,
    clientId: values.azureAppGwClientId?.trim() || undefined,
    resourceGroup: values.azureAppGwResourceGroup,
    appGateway: values.azureAppGwAppGateway,
    listeners,
    keyVaultUri: values.azureAppGwKeyVaultUri,
  });

  if (!result.success) {
    for (const issue of result.error.issues) {
      const field = issue.path[0];
      if (typeof field !== "string") {
        continue;
      }
      const map: Record<string, keyof CredentialFormValidationValues> = {
        tenantId: "azureAppGwTenantId",
        subscriptionId: "azureAppGwSubscriptionId",
        clientId: "azureAppGwClientId",
        resourceGroup: "azureAppGwResourceGroup",
        appGateway: "azureAppGwAppGateway",
        listeners: "azureAppGwListeners",
        keyVaultUri: "azureAppGwKeyVaultUri",
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
