// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import type { FieldValues, UseFormReturn } from "react-hook-form";

import { StringListFormField } from "@/components/common/string-list-form-field";
import {
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";

export function F5BigipFields<TFieldValues extends FieldValues>({
  form,
}: {
  form: UseFormReturn<TFieldValues>;
}) {
  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2">
        <FormField
          control={form.control}
          name={"f5BigipHost" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>BIG-IP host</FormLabel>
              <FormControl>
                <Input
                  className="h-10"
                  placeholder="bigip.example.com"
                  {...field}
                />
              </FormControl>
              <p className="text-xs text-muted-foreground">
                Use a hostname or IP (no protocol, path, or trailing slash).
              </p>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name={"f5BigipPartition" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>Partition</FormLabel>
              <FormControl>
                <Input className="h-10" placeholder="Common" {...field} />
              </FormControl>
              <p className="text-xs text-muted-foreground">
                BIG-IP connection defaults (port, TLS verification, HA sync, and
                profile discovery) are configured server-side.
              </p>
              <FormMessage />
            </FormItem>
          )}
        />
      </div>

      <StringListFormField
        form={form}
        name={"f5BigipClientSslProfiles" as never}
        label="Client SSL profiles (optional)"
        placeholder="clientssl-api"
        addLabel="Add profile"
      />
    </div>
  );
}
