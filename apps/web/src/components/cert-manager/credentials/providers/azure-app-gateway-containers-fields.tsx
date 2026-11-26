// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import type { FieldValues, UseFormReturn } from "react-hook-form";

import {
  AZURE_AGC_API_STYLES,
  AZURE_AGC_AUTH_MODES,
  AZURE_AGC_CLUSTER_AUTH_MODES,
  type AzureAgcApiStyle,
  type AzureAgcAuthMode,
  type AzureAgcClusterAuthMode,
} from "@/lib/credential-config-schemas/azure-agc";
import { StringListFormField } from "@/components/common/string-list-form-field";
import {
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { AuthModeSelect } from "@/components/cert-manager/credentials/providers/auth-mode-select";
import { AzureServicePrincipalClientIdField } from "@/components/cert-manager/credentials/providers/azure-service-principal-client-id-field";

const getAzureAuthModeLabel = (mode: AzureAgcAuthMode): string =>
  mode === "SERVICE_PRINCIPAL" ? "Service principal" : "Workload identity";

export function AzureAppGatewayContainersFields<
  TFieldValues extends FieldValues,
>({
  form,
  azureAuthMode,
  clusterAuthMode,
  apiStyle,
  allowedAzureAuthModes = AZURE_AGC_AUTH_MODES,
  showServicePrincipalClientId = false,
}: {
  form: UseFormReturn<TFieldValues>;
  azureAuthMode: AzureAgcAuthMode;
  clusterAuthMode: AzureAgcClusterAuthMode;
  apiStyle: AzureAgcApiStyle;
  allowedAzureAuthModes?: readonly AzureAgcAuthMode[];
  showServicePrincipalClientId?: boolean;
}) {
  const requiresAzureArmCoords = clusterAuthMode === "AZURE";

  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2">
        <AuthModeSelect
          allowedModes={allowedAzureAuthModes}
          authMode={azureAuthMode}
          form={form}
          getLabel={getAzureAuthModeLabel}
          infoProvider="AZURE_KV"
          modes={AZURE_AGC_AUTH_MODES}
          name="azureAgcAzureAuthMode"
        />

        <FormField
          control={form.control}
          name={"azureAgcClusterAuthMode" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>Cluster auth mode</FormLabel>
              <Select onValueChange={field.onChange} value={field.value}>
                <FormControl>
                  <SelectTrigger className="h-10">
                    <SelectValue placeholder="Select cluster auth" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {AZURE_AGC_CLUSTER_AUTH_MODES.map((mode) => (
                    <SelectItem key={mode} value={mode}>
                      {mode === "AZURE"
                        ? "Azure (AKS kubeconfig via ARM)"
                        : "In-cluster (service account)"}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />
      </div>

      {requiresAzureArmCoords ? (
        <div className="grid gap-4 md:grid-cols-2">
          <FormField
            control={form.control}
            name={"azureAgcTenantId" as never}
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
            name={"azureAgcSubscriptionId" as never}
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
      ) : null}

      {showServicePrincipalClientId && azureAuthMode === "SERVICE_PRINCIPAL" ? (
        <AzureServicePrincipalClientIdField
          form={form}
          name={"azureAgcClientId" as never}
        />
      ) : null}

      {azureAuthMode === "WORKLOAD_IDENTITY" ? (
        <FormField
          control={form.control}
          name={"azureAgcClientId" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>Client ID</FormLabel>
              <FormControl>
                <Input className="h-10 md:max-w-xl" {...field} />
              </FormControl>
              <p className="text-xs text-muted-foreground">
                Only needed when multiple identities exist or when the runtime
                is not configured with a default client ID.
              </p>
              <FormMessage />
            </FormItem>
          )}
        />
      ) : null}

      {requiresAzureArmCoords ? (
        <FormField
          control={form.control}
          name={"azureAgcResourceGroup" as never}
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
      ) : null}

      <div className="grid gap-4 md:grid-cols-2">
        <FormField
          control={form.control}
          name={"azureAgcClusterName" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>Cluster name</FormLabel>
              <FormControl>
                <Input className="h-10" placeholder="aks-prod" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name={"azureAgcNamespace" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>AGC namespace</FormLabel>
              <FormControl>
                <Input className="h-10" placeholder="alb-system" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
      </div>

      <FormField
        control={form.control}
        name={"azureAgcApiStyle" as never}
        render={({ field }) => (
          <FormItem>
            <FormLabel>API style</FormLabel>
            <Select
              onValueChange={field.onChange}
              value={field.value || apiStyle}
            >
              <FormControl>
                <SelectTrigger className="h-10 md:max-w-sm">
                  <SelectValue placeholder="Select API style" />
                </SelectTrigger>
              </FormControl>
              <SelectContent>
                {AZURE_AGC_API_STYLES.map((style) => (
                  <SelectItem key={style} value={style}>
                    {style === "GATEWAY_API" ? "Gateway API" : "Ingress"}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FormMessage />
          </FormItem>
        )}
      />

      <StringListFormField
        form={form}
        name={"azureAgcSecretNamespaces" as never}
        label="Allowed secret namespaces"
        placeholder="app-prod"
        addLabel="Add namespace"
      />
    </div>
  );
}
