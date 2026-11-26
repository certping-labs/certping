// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import type { FieldValues, UseFormReturn } from "react-hook-form";

import type { AwsApiGwAuthMode } from "@/lib/credential-config-schemas/aws-api-gateway";
import { AwsApiGatewayFields } from "@/components/cert-manager/credentials/providers/aws-api-gateway-fields-shared";

export function AwsApiGwHttpFields<TFieldValues extends FieldValues>({
  form,
  authMode,
  allowedAuthModes,
}: {
  form: UseFormReturn<TFieldValues>;
  authMode: AwsApiGwAuthMode;
  allowedAuthModes?: readonly AwsApiGwAuthMode[];
}) {
  return (
    <AwsApiGatewayFields
      form={form}
      authMode={authMode}
      providerLabel="HTTP/WebSocket API"
      allowedAuthModes={allowedAuthModes}
    />
  );
}
