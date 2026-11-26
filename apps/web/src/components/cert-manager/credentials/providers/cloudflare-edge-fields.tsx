// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import type { FieldValues, UseFormReturn } from "react-hook-form";

import {
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";

export function CloudflareEdgeFields<TFieldValues extends FieldValues>({
  form,
}: {
  form: UseFormReturn<TFieldValues>;
}) {
  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2">
        <FormField
          control={form.control}
          name={"cloudflareZoneId" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>Zone ID</FormLabel>
              <FormControl>
                <Input className="h-10" placeholder="abc123zoneid" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
      </div>
    </div>
  );
}
