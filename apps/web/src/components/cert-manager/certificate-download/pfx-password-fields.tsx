// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import type { Control } from "react-hook-form";

import { Checkbox } from "@/components/ui/checkbox";
import {
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import type { CertificateExportFormValues } from "@/lib/cert-manager/certificate-export-form";

interface PfxPasswordFieldsProps {
  control: Control<CertificateExportFormValues>;
  disabled: boolean;
  /** Called when the user changes any of these fields. */
  onEdit: () => void;
}

/**
 * Password, confirmation, and the legacy-encryption switch for a PFX file.
 * The inputs have no `maxLength`: a silently truncated paste would set a
 * password the user never typed, so the schema reports the limit instead.
 */
export function PfxPasswordFields({
  control,
  disabled,
  onEdit,
}: PfxPasswordFieldsProps) {
  return (
    <fieldset className="space-y-4" disabled={disabled}>
      <legend className="sr-only">PFX file password</legend>
      <FormField
        control={control}
        name="password"
        render={({ field }) => (
          <FormItem>
            <FormLabel>File password</FormLabel>
            <FormControl>
              <Input
                {...field}
                onChange={(event) => {
                  field.onChange(event);
                  onEdit();
                }}
                type="password"
                autoComplete="new-password"
                className="h-11"
              />
            </FormControl>
            <FormDescription className="text-xs">
              At least 8 characters. You&apos;ll need it to import the file.
            </FormDescription>
            <FormMessage role="alert" />
          </FormItem>
        )}
      />
      <FormField
        control={control}
        name="confirmPassword"
        render={({ field }) => (
          <FormItem>
            <FormLabel>Confirm password</FormLabel>
            <FormControl>
              <Input
                {...field}
                onChange={(event) => {
                  field.onChange(event);
                  onEdit();
                }}
                type="password"
                autoComplete="new-password"
                className="h-11"
              />
            </FormControl>
            <FormMessage role="alert" />
          </FormItem>
        )}
      />
      <FormField
        control={control}
        name="legacyPkcs12"
        render={({ field }) => (
          <FormItem className="flex min-h-11 items-start gap-3 space-y-0">
            <FormControl>
              <Checkbox
                checked={field.value}
                onCheckedChange={(checked) => {
                  field.onChange(checked === true);
                  onEdit();
                }}
                className="mt-0.5"
              />
            </FormControl>
            <div className="space-y-0.5">
              <FormLabel className="font-medium">
                Legacy compatibility (Windows Server 2016 and older)
              </FormLabel>
              <FormDescription className="text-xs leading-5">
                Uses older encryption that Windows Server 2016 and OpenSSL 1.0
                can import. Leave this off unless the import fails.
              </FormDescription>
            </div>
          </FormItem>
        )}
      />
    </fieldset>
  );
}
