// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import type { FieldValues, Path, UseFormReturn } from "react-hook-form";

import {
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";

export const AZURE_WORKLOAD_IDENTITY_CLIENT_ID_HELP =
  "Client ID of the workload identity (the user-assigned managed identity or app registration federated with the agent's service account).";

interface AzureServicePrincipalClientIdFieldProps<
  TFieldValues extends FieldValues,
> {
  description?: string;
  form: UseFormReturn<TFieldValues>;
  name: Path<TFieldValues>;
}

export function AzureServicePrincipalClientIdField<
  TFieldValues extends FieldValues,
>({
  description = "Used with the client secret for Azure service-principal authentication.",
  form,
  name,
}: AzureServicePrincipalClientIdFieldProps<TFieldValues>) {
  return (
    <FormField
      control={form.control}
      name={name}
      render={({ field }) => (
        <FormItem>
          <FormLabel>Client ID</FormLabel>
          <FormControl>
            <Input className="h-10 md:max-w-xl" {...field} />
          </FormControl>
          <p className="text-xs text-muted-foreground">{description}</p>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}
