// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import type { FieldValues, UseFormReturn } from "react-hook-form";

import {
  AZURE_KV_AUTH_MODES,
  getAzureKvAuthModeHelp,
  getAzureKvAuthModeLabel,
  type AzureKvAuthMode,
} from "@/lib/credential-config-schemas/azure-kv";
import {
  FormControl,
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

export function AzureKvFields<TFieldValues extends FieldValues>({
  form,
  authMode,
  allowedAuthModes = AZURE_KV_AUTH_MODES,
}: {
  form: UseFormReturn<TFieldValues>;
  authMode: AzureKvAuthMode;
  allowedAuthModes?: readonly AzureKvAuthMode[];
}) {
  return (
    <div className="space-y-4">
      <AuthModeSelect
        allowedModes={allowedAuthModes}
        authMode={authMode}
        form={form}
        getHelpText={getAzureKvAuthModeHelp}
        getLabel={getAzureKvAuthModeLabel}
        infoProvider="AZURE_KV"
        modes={AZURE_KV_AUTH_MODES}
        name="azureKvAuthMode"
      />

      <div className="grid gap-4 md:grid-cols-2">
        <FormField
          control={form.control}
          name={"azureKvVaultUri" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>Vault URI</FormLabel>
              <FormControl>
                <Input className="h-10" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name={"azureKvTenantId" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>Tenant ID</FormLabel>
              <FormControl>
                <Input className="h-10 md:max-w-sm" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
      </div>

      {authMode === "WORKLOAD_IDENTITY" ? (
        <AzureServicePrincipalClientIdField
          description={AZURE_WORKLOAD_IDENTITY_CLIENT_ID_HELP}
          form={form}
          name={"azureKvClientId" as never}
        />
      ) : null}
    </div>
  );
}
