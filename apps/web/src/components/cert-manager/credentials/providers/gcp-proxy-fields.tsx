// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import type { FieldValues, UseFormReturn } from "react-hook-form";

import {
  GCP_AUTH_MODES,
  getGcpAuthModeHelp,
  getGcpAuthModeLabel,
  type GcpAuthMode,
} from "@/lib/credential-config-schemas/gcp-shared";
import {
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { AuthModeSelect } from "@/components/cert-manager/credentials/providers/auth-mode-select";

export function GcpProxyFields<TFieldValues extends FieldValues>({
  form,
  authMode,
  providerApiValue,
  allowedAuthModes = GCP_AUTH_MODES,
}: {
  form: UseFormReturn<TFieldValues>;
  authMode: GcpAuthMode;
  providerApiValue: string;
  allowedAuthModes?: readonly GcpAuthMode[];
}) {
  const normalized = (providerApiValue || "").trim().toUpperCase();
  const proxyLabel =
    normalized === "GCP_PROXY_NLB" ? "Target SSL proxy" : "Target HTTPS proxy";
  const proxyFieldName =
    normalized === "GCP_PROXY_NLB"
      ? ("gcpProxyTargetSslProxy" as const)
      : ("gcpProxyTargetHttpsProxy" as const);

  return (
    <div className="space-y-4">
      <AuthModeSelect
        allowedModes={allowedAuthModes}
        authMode={authMode}
        form={form}
        getHelpText={getGcpAuthModeHelp}
        getLabel={getGcpAuthModeLabel}
        infoProvider="GCP"
        modes={GCP_AUTH_MODES}
        name="gcpAuthMode"
      />

      <div className="grid gap-4 md:grid-cols-2">
        <FormField
          control={form.control}
          name={"gcpProjectId" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>Project ID</FormLabel>
              <FormControl>
                <Input className="h-10 md:max-w-sm" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name={"gcpLocation" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>Location</FormLabel>
              <FormControl>
                <Input
                  className="h-10 md:max-w-sm"
                  placeholder="global"
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
      </div>

      {authMode === "IMPERSONATE_SERVICE_ACCOUNT" ? (
        <FormField
          control={form.control}
          name={"gcpImpersonateServiceAccount" as never}
          render={({ field }) => (
            <FormItem>
              <FormLabel>Impersonate service account (optional)</FormLabel>
              <FormControl>
                <Input
                  className="h-10"
                  placeholder="sa@project.iam.gserviceaccount.com"
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
      ) : null}

      <FormField
        control={form.control}
        name={proxyFieldName as never}
        render={({ field }) => (
          <FormItem>
            <FormLabel>{proxyLabel}</FormLabel>
            <FormControl>
              <Input
                className="h-10 md:max-w-sm"
                placeholder="proxy-name"
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
