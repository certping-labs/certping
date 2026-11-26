// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import type { FieldValues, UseFormReturn } from "react-hook-form";

import {
  AWS_API_GW_AUTH_MODES,
  getAwsApiGatewayAuthModeHelp,
  getAwsApiGatewayAuthModeLabel,
  type AwsApiGwAuthMode,
} from "@/lib/credential-config-schemas/aws-api-gateway";
import {
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { StringListFormField } from "@/components/common/string-list-form-field";
import { AuthModeSelect } from "@/components/cert-manager/credentials/providers/auth-mode-select";

export function AwsApiGatewayFields<TFieldValues extends FieldValues>({
  form,
  authMode,
  providerLabel,
  allowedAuthModes = AWS_API_GW_AUTH_MODES,
}: {
  form: UseFormReturn<TFieldValues>;
  authMode: AwsApiGwAuthMode;
  providerLabel: string;
  allowedAuthModes?: readonly AwsApiGwAuthMode[];
}) {
  return (
    <div className="space-y-4">
      <AuthModeSelect
        allowedModes={allowedAuthModes}
        authMode={authMode}
        form={form}
        getHelpText={getAwsApiGatewayAuthModeHelp}
        getLabel={getAwsApiGatewayAuthModeLabel}
        infoProvider="AWS_ACM"
        modes={AWS_API_GW_AUTH_MODES}
        name="awsApiGwAuthMode"
      />

      <div className="grid gap-4 md:grid-cols-2">
        <FormField
          control={form.control}
          name={"awsApiGwRegion" as never}
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
            name={"awsApiGwRoleArn" as never}
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
          name={"awsApiGwExternalId" as never}
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

      <StringListFormField
        form={form}
        name={"awsApiGwCustomDomains" as never}
        label={`${providerLabel} custom domains`}
        placeholder="api.example.com"
        addLabel="Add domain"
      />
    </div>
  );
}
