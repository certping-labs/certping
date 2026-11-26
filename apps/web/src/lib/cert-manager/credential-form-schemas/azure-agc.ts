// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  azureAgcCredentialConfigSchema,
  isAzureAgcKvPathRequired,
  isAzureAgcProvider,
  type AzureAgcAuthMode,
  type AzureAgcClusterAuthMode,
} from "@/lib/credential-config-schemas/azure-agc";
import type {
  CredentialFormValidationValues,
  SchemaRefinementContext,
} from "@/lib/cert-manager/credential-form-schemas/types";

export function isAzureAgcCredentialProvider(provider?: string): boolean {
  return isAzureAgcProvider(provider);
}

export function isAzureAgcCredentialKvPathRequired(
  values: CredentialFormValidationValues,
): boolean {
  const azureAuthMode = (values.azureAgcAzureAuthMode ||
    "SERVICE_PRINCIPAL") as AzureAgcAuthMode;
  const clusterAuthMode = (values.azureAgcClusterAuthMode ||
    "AZURE") as AzureAgcClusterAuthMode;
  return isAzureAgcKvPathRequired({ azureAuthMode, clusterAuthMode });
}

export function validateAzureAgcCredentialFields(
  values: CredentialFormValidationValues,
  context: SchemaRefinementContext,
): void {
  const secretNamespaces = (values.azureAgcSecretNamespaces || [])
    .map((value) => value.trim())
    .filter((value) => value.length > 0);

  const result = azureAgcCredentialConfigSchema.safeParse({
    azureAuthMode: (values.azureAgcAzureAuthMode ||
      "SERVICE_PRINCIPAL") as AzureAgcAuthMode,
    tenantId: values.azureAgcTenantId,
    subscriptionId: values.azureAgcSubscriptionId,
    resourceGroup: values.azureAgcResourceGroup,
    clientId: values.azureAgcClientId?.trim() || undefined,
    clusterAuthMode: (values.azureAgcClusterAuthMode ||
      "AZURE") as AzureAgcClusterAuthMode,
    clusterName: values.azureAgcClusterName,
    agcNamespace: values.azureAgcNamespace,
    apiStyle: values.azureAgcApiStyle,
    secretNamespaces,
  });

  if (!result.success) {
    for (const issue of result.error.issues) {
      const field = issue.path[0];
      if (typeof field !== "string") {
        continue;
      }
      const map: Record<string, keyof CredentialFormValidationValues> = {
        azureAuthMode: "azureAgcAzureAuthMode",
        tenantId: "azureAgcTenantId",
        subscriptionId: "azureAgcSubscriptionId",
        resourceGroup: "azureAgcResourceGroup",
        clientId: "azureAgcClientId",
        clusterAuthMode: "azureAgcClusterAuthMode",
        clusterName: "azureAgcClusterName",
        agcNamespace: "azureAgcNamespace",
        apiStyle: "azureAgcApiStyle",
        secretNamespaces: "azureAgcSecretNamespaces",
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
