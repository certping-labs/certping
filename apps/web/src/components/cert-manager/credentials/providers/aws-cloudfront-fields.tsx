// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import type { FieldValues, UseFormReturn } from "react-hook-form";

import {
  AWS_CLOUDFRONT_AUTH_MODES,
  getAwsCloudFrontAuthModeHelp,
  getAwsCloudFrontAuthModeLabel,
  type AwsCloudFrontAuthMode,
} from "@/lib/credential-config-schemas/aws-cloudfront";
import {
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { AuthModeSelect } from "@/components/cert-manager/credentials/providers/auth-mode-select";

export function AwsCloudFrontFields<TFieldValues extends FieldValues>({
  form,
  authMode,
  allowedAuthModes = AWS_CLOUDFRONT_AUTH_MODES,
}: {
  form: UseFormReturn<TFieldValues>;
  authMode: AwsCloudFrontAuthMode;
  allowedAuthModes?: readonly AwsCloudFrontAuthMode[];
}) {
  return (
    <div className="space-y-4">
      <AuthModeSelect
        allowedModes={allowedAuthModes}
        authMode={authMode}
        form={form}
        getHelpText={getAwsCloudFrontAuthModeHelp}
        getLabel={getAwsCloudFrontAuthModeLabel}
        infoProvider="AWS_ACM"
        modes={AWS_CLOUDFRONT_AUTH_MODES}
        name="awsCloudFrontAuthMode"
      />

      <FormField
        control={form.control}
        name={"awsCloudFrontDistributionId" as never}
        render={({ field }) => (
          <FormItem>
            <FormLabel>Distribution ID</FormLabel>
            <FormControl>
              <Input className="h-10 md:max-w-xl" {...field} />
            </FormControl>
            <FormMessage />
          </FormItem>
        )}
      />

      {authMode === "ASSUME_ROLE" ? (
        <>
          <FormField
            control={form.control}
            name={"awsCloudFrontRoleArn" as never}
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
          <FormField
            control={form.control}
            name={"awsCloudFrontExternalId" as never}
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
        </>
      ) : null}
    </div>
  );
}
