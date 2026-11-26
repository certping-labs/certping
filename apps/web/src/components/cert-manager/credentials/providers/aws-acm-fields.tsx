// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import type { FieldValues, UseFormReturn } from "react-hook-form";

import {
  AWS_ACM_AUTH_MODES,
  getAwsAcmAuthModeHelp,
  getAwsAcmAuthModeLabel,
  type AwsAcmAuthMode,
} from "@/lib/credential-config-schemas/aws-acm";
import {
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { AuthModeSelect } from "@/components/cert-manager/credentials/providers/auth-mode-select";

export function AwsAcmFields<TFieldValues extends FieldValues>({
  form,
  authMode,
  allowedAuthModes = AWS_ACM_AUTH_MODES,
}: {
  form: UseFormReturn<TFieldValues>;
  authMode: AwsAcmAuthMode;
  allowedAuthModes?: readonly AwsAcmAuthMode[];
}) {
  return (
    <div className="space-y-4">
      <AuthModeSelect
        allowedModes={allowedAuthModes}
        authMode={authMode}
        form={form}
        getHelpText={getAwsAcmAuthModeHelp}
        getLabel={getAwsAcmAuthModeLabel}
        infoProvider="AWS_ACM"
        modes={AWS_ACM_AUTH_MODES}
        name="awsAcmAuthMode"
      />

      <div className="grid gap-4 md:grid-cols-2">
        <FormField
          control={form.control}
          name={"awsAcmRegion" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>Region</FormLabel>
              <FormControl>
                <Input className="h-10 md:max-w-sm" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {authMode === "ASSUME_ROLE" ? (
          <FormField
            control={form.control}
            name={"awsAcmRoleArn" as never}
            render={({ field }) => (
              <FormItem>
                <FormLabel>Role ARN</FormLabel>
                <FormControl>
                  <Input className="h-10" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        ) : null}
      </div>

      {authMode === "ASSUME_ROLE" ? (
        <FormField
          control={form.control}
          name={"awsAcmExternalId" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>External ID (optional)</FormLabel>
              <FormControl>
                <Input className="h-10 md:max-w-sm" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
      ) : null}
    </div>
  );
}
