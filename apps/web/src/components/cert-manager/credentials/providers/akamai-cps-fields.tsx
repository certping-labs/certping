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

export function AkamaiCpsFields<TFieldValues extends FieldValues>({
  form,
}: {
  form: UseFormReturn<TFieldValues>;
}) {
  return (
    <div className="space-y-4">
      <FormField
        control={form.control}
        name={"akamaiHost" as never}
        render={({ field }) => (
          <FormItem>
            <FormLabel>EdgeGrid host</FormLabel>
            <FormControl>
              <Input
                className="h-10 md:max-w-sm"
                placeholder="akab-xxxxx.luna.akamaiapis.net"
                {...field}
              />
            </FormControl>
            <FormMessage />
          </FormItem>
        )}
      />

      <FormField
        control={form.control}
        name={"akamaiEnrollmentId" as never}
        render={({ field }) => (
          <FormItem>
            <FormLabel>Enrollment ID</FormLabel>
            <FormControl>
              <Input
                className="h-10 md:max-w-sm"
                placeholder="123456"
                {...field}
              />
            </FormControl>
            <FormMessage />
          </FormItem>
        )}
      />
    </div>
  );
}
