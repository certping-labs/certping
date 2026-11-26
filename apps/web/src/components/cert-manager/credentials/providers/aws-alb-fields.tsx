// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import type { FieldValues, UseFormReturn } from "react-hook-form";

import type { AwsLoadBalancerAuthMode } from "@/lib/credential-config-schemas/aws-load-balancer";
import { AwsLoadBalancerFields } from "@/components/cert-manager/credentials/providers/aws-load-balancer-fields";

export function AwsAlbFields<TFieldValues extends FieldValues>({
  form,
  authMode,
  allowedAuthModes,
}: {
  form: UseFormReturn<TFieldValues>;
  authMode: AwsLoadBalancerAuthMode;
  allowedAuthModes?: readonly AwsLoadBalancerAuthMode[];
}) {
  return (
    <AwsLoadBalancerFields
      form={form}
      authMode={authMode}
      allowedAuthModes={allowedAuthModes}
    />
  );
}
