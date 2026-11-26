// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import type { FieldValues, UseFormReturn } from "react-hook-form";

import { CredentialAuthModeInfoDialog } from "@/components/cert-manager/credentials/credential-auth-mode-info-dialog";
import {
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

type AuthModeInfoProvider = "AWS_ACM" | "AZURE_KV" | "GCP";

interface AuthModeSelectProps<
  TFieldValues extends FieldValues,
  TMode extends string,
> {
  allowedModes?: readonly TMode[];
  authMode: TMode;
  form: UseFormReturn<TFieldValues>;
  getHelpText?: (mode: TMode) => string;
  getLabel: (mode: TMode) => string;
  infoProvider: AuthModeInfoProvider;
  name: string;
  modes: readonly TMode[];
}

export function AuthModeSelect<
  TFieldValues extends FieldValues,
  TMode extends string,
>({
  allowedModes,
  authMode,
  form,
  getHelpText,
  getLabel,
  infoProvider,
  name,
  modes,
}: AuthModeSelectProps<TFieldValues, TMode>) {
  const shouldRestrictModes = Boolean(allowedModes);
  const allowedModeSet = new Set(allowedModes ?? modes);
  const fallbackMode = allowedModeSet.has(authMode)
    ? authMode
    : (allowedModes ?? modes)[0];
  const modeOptions = modes.filter((mode) => allowedModeSet.has(mode));
  const getSelectedValue = (value: TMode): TMode => {
    if (!shouldRestrictModes) {
      return value;
    }
    return allowedModeSet.has(value) ? value : fallbackMode;
  };

  return (
    <FormField
      control={form.control}
      name={name as never}
      render={({ field }) => (
        <FormItem>
          <div className="flex items-center justify-between gap-2">
            <FormLabel>Auth mode</FormLabel>
            <CredentialAuthModeInfoDialog provider={infoProvider} />
          </div>
          <Select
            onValueChange={(value) => field.onChange(value || fallbackMode)}
            value={getSelectedValue(field.value)}
          >
            <FormControl>
              <SelectTrigger className="h-10 md:max-w-sm">
                <SelectValue placeholder="Select auth mode" />
              </SelectTrigger>
            </FormControl>
            <SelectContent>
              {modeOptions.map((mode) => (
                <SelectItem key={mode} value={mode}>
                  {getLabel(mode)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {getHelpText ? (
            <p className="text-xs text-muted-foreground">
              {getHelpText(authMode)}
            </p>
          ) : null}
          <FormMessage />
        </FormItem>
      )}
    />
  );
}
