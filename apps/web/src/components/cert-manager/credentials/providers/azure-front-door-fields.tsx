// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import type { FieldValues, UseFormReturn } from "react-hook-form";

import {
  AZURE_AFD_AUTH_MODES,
  type AzureAfdAuthMode,
} from "@/lib/credential-config-schemas/azure-afd";
import { StringListFormField } from "@/components/common/string-list-form-field";
import {
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { AuthModeSelect } from "@/components/cert-manager/credentials/providers/auth-mode-select";
import {
  AZURE_WORKLOAD_IDENTITY_CLIENT_ID_HELP,
  AzureServicePrincipalClientIdField,
} from "@/components/cert-manager/credentials/providers/azure-service-principal-client-id-field";

const getAzureAuthModeLabel = (mode: AzureAfdAuthMode): string =>
  mode === "SERVICE_PRINCIPAL" ? "Service principal" : "Workload identity";

const getAzureAuthModeHelp = (mode: AzureAfdAuthMode): string =>
  mode === "WORKLOAD_IDENTITY"
    ? "Uses Azure workload identity at runtime; secret handle is optional."
    : "Uses client credentials from the secret handle for Azure SDK authentication.";

export function AzureFrontDoorFields<TFieldValues extends FieldValues>({
  form,
  authMode,
  allowedAuthModes = AZURE_AFD_AUTH_MODES,
  showServicePrincipalClientId = false,
  showKeyVaultUri = true,
}: {
  form: UseFormReturn<TFieldValues>;
  authMode: AzureAfdAuthMode;
  allowedAuthModes?: readonly AzureAfdAuthMode[];
  showServicePrincipalClientId?: boolean;
  showKeyVaultUri?: boolean;
}) {
  return (
    <div className="space-y-4">
      <AuthModeSelect
        allowedModes={allowedAuthModes}
        authMode={authMode}
        form={form}
        getHelpText={getAzureAuthModeHelp}
        getLabel={getAzureAuthModeLabel}
        infoProvider="AZURE_KV"
        modes={AZURE_AFD_AUTH_MODES}
        name="azureAfdAuthMode"
      />

      <div className="grid gap-4 md:grid-cols-2">
        <FormField
          control={form.control}
          name={"azureAfdTenantId" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>Tenant ID</FormLabel>
              <FormControl>
                <Input className="h-10" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name={"azureAfdSubscriptionId" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>Subscription ID</FormLabel>
              <FormControl>
                <Input className="h-10" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
      </div>

      {showServicePrincipalClientId && authMode === "SERVICE_PRINCIPAL" ? (
        <AzureServicePrincipalClientIdField
          form={form}
          name={"azureAfdClientId" as never}
        />
      ) : null}

      {authMode === "WORKLOAD_IDENTITY" ? (
        <AzureServicePrincipalClientIdField
          description={AZURE_WORKLOAD_IDENTITY_CLIENT_ID_HELP}
          form={form}
          name={"azureAfdClientId" as never}
        />
      ) : null}

      <div className="grid gap-4 md:grid-cols-2">
        <FormField
          control={form.control}
          name={"azureAfdResourceGroup" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>Resource group</FormLabel>
              <FormControl>
                <Input className="h-10" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name={"azureAfdProfileName" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>AFD profile name</FormLabel>
              <FormControl>
                <Input className="h-10" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
      </div>

      {showKeyVaultUri ? (
        <FormField
          control={form.control}
          name={"azureAfdKeyVaultUri" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>Key Vault URI</FormLabel>
              <FormControl>
                <Input
                  className="h-10"
                  placeholder="https://my-kv.vault.azure.net/"
                  {...field}
                />
              </FormControl>
              <FormDescription className="text-xs">
                URI of the Key Vault where this target should read the deployed
                certificate.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
      ) : null}

      <StringListFormField
        form={form}
        name={"azureAfdCustomDomains" as never}
        label="Custom domains"
        placeholder="api.example.com"
        addLabel="Add custom domain"
        description="Hostnames of the Front Door custom domains, for example api.example.com."
      />
    </div>
  );
}
