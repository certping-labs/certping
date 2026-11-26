// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import type { FieldValues, UseFormReturn } from "react-hook-form";

import {
  KUBERNETES_AUTH_METHODS,
  getKubernetesAuthMethodInstruction,
  getKubernetesAuthMethodLabel,
  type KubernetesAuthMethod,
} from "@/lib/credential-config-schemas/kubernetes-secrets";
import { CredentialProviderInfoDialog } from "@/components/cert-manager/credentials/credential-provider-info-dialog";
import { StringListFormField } from "@/components/common/string-list-form-field";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const K8S_AUTH_METHOD_OPTIONS: Array<{
  value: KubernetesAuthMethod;
  label: string;
}> = KUBERNETES_AUTH_METHODS.map((value) => ({
  value,
  label: getKubernetesAuthMethodLabel(value),
}));

export function KubernetesSecretsFields<TFieldValues extends FieldValues>({
  form,
  authMethod,
  showStorageInstruction = true,
  allowedAuthMethods = KUBERNETES_AUTH_METHODS,
}: {
  form: UseFormReturn<TFieldValues>;
  authMethod: KubernetesAuthMethod;
  showStorageInstruction?: boolean;
  allowedAuthMethods?: readonly KubernetesAuthMethod[];
}) {
  const namespaceMode = form.watch("k8sNamespaceMode" as never) as unknown as
    "explicit" | "all_namespaces" | undefined;
  const allowedAuthMethodSet = new Set(allowedAuthMethods);
  const fallbackAuthMethod = allowedAuthMethodSet.has(authMethod)
    ? authMethod
    : allowedAuthMethods[0] || "AZURE";
  const authMethodOptions = K8S_AUTH_METHOD_OPTIONS.filter((option) =>
    allowedAuthMethodSet.has(option.value),
  );

  return (
    <div className="space-y-4">
      <FormField
        control={form.control}
        name={"k8sAuthMethod" as never}
        render={({ field }) => (
          <FormItem>
            <div className="flex items-center justify-between gap-2">
              <FormLabel>Auth method</FormLabel>
              <CredentialProviderInfoDialog
                kubernetesAuthMethod={authMethod}
                providerApiValue="KUBERNETES_SECRETS"
              />
            </div>
            <Select
              onValueChange={(value) =>
                field.onChange(value || fallbackAuthMethod)
              }
              value={
                allowedAuthMethodSet.has(field.value)
                  ? field.value
                  : fallbackAuthMethod
              }
            >
              <FormControl>
                <SelectTrigger className="h-10 md:max-w-sm">
                  <SelectValue placeholder="Select auth method" />
                </SelectTrigger>
              </FormControl>
              <SelectContent>
                {authMethodOptions.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FormMessage />
          </FormItem>
        )}
      />

      <div className="grid gap-4 md:grid-cols-2">
        <FormField
          control={form.control}
          name={"k8sClusterName" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>Cluster name</FormLabel>
              <FormControl>
                <Input className="h-10 md:max-w-sm" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name={"k8sNamespaceMode" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>Namespace scope</FormLabel>
              <FormControl>
                <RadioGroup
                  value={field.value}
                  onValueChange={field.onChange}
                  className="grid gap-2 md:max-w-sm"
                >
                  <div className="flex items-center gap-2">
                    <RadioGroupItem value="explicit" id="k8s-ns-explicit" />
                    <Label htmlFor="k8s-ns-explicit">Specific namespaces</Label>
                  </div>
                  <div className="flex items-center gap-2">
                    <RadioGroupItem value="all_namespaces" id="k8s-ns-all" />
                    <Label htmlFor="k8s-ns-all">All namespaces</Label>
                  </div>
                </RadioGroup>
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
      </div>

      {namespaceMode !== "all_namespaces" ? (
        <StringListFormField
          form={form}
          name={"k8sNamespaces" as never}
          label="Namespaces"
          placeholder="prod"
          addLabel="Add namespace"
        />
      ) : null}

      {showStorageInstruction ? (
        <Alert>
          <AlertTitle>{getKubernetesAuthMethodLabel(authMethod)}</AlertTitle>
          <AlertDescription>
            {getKubernetesAuthMethodInstruction(authMethod)}
          </AlertDescription>
        </Alert>
      ) : null}
    </div>
  );
}
