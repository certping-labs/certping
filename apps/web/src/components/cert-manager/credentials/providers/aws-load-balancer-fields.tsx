// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import type { FieldValues, UseFormReturn } from "react-hook-form";

import {
  AWS_LOAD_BALANCER_AUTH_MODES,
  getAwsLoadBalancerAuthModeHelp,
  getAwsLoadBalancerAuthModeLabel,
  type AwsLoadBalancerAuthMode,
} from "@/lib/credential-config-schemas/aws-load-balancer";
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

export function AwsLoadBalancerFields<TFieldValues extends FieldValues>({
  form,
  authMode,
  allowedAuthModes = AWS_LOAD_BALANCER_AUTH_MODES,
}: {
  form: UseFormReturn<TFieldValues>;
  authMode: AwsLoadBalancerAuthMode;
  allowedAuthModes?: readonly AwsLoadBalancerAuthMode[];
}) {
  return (
    <div className="space-y-4">
      <AuthModeSelect
        allowedModes={allowedAuthModes}
        authMode={authMode}
        form={form}
        getHelpText={getAwsLoadBalancerAuthModeHelp}
        getLabel={getAwsLoadBalancerAuthModeLabel}
        infoProvider="AWS_ACM"
        modes={AWS_LOAD_BALANCER_AUTH_MODES}
        name="awsElbAuthMode"
      />

      <div className="grid gap-4 md:grid-cols-2">
        <FormField
          control={form.control}
          name={"awsElbRegion" as never}
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
            name={"awsElbRoleArn" as never}
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
          name={"awsElbExternalId" as never}
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
        name={"awsElbListeners" as never}
        label="Listener ARNs"
        placeholder="arn:aws:elasticloadbalancing:...:listener/..."
        addLabel="Add listener ARN"
      />
    </div>
  );
}
