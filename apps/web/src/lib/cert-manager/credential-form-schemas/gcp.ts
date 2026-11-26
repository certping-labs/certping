// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

import {
  GCP_AUTH_MODES,
  type GcpAuthMode,
} from "@/lib/credential-config-schemas/gcp-shared";
import {
  gcpCertManagerCredentialConfigSchema,
  isGcpCertManagerProvider,
} from "@/lib/credential-config-schemas/gcp-cert-manager";
import {
  gcpProxyCredentialConfigSchema,
  isGcpProxyProvider,
} from "@/lib/credential-config-schemas/gcp-proxy";
import type {
  CredentialFormValidationValues,
  SchemaRefinementContext,
} from "@/lib/cert-manager/credential-form-schemas/types";

export function isGcpCredentialProvider(provider?: string): boolean {
  return isGcpCertManagerProvider(provider) || isGcpProxyProvider(provider);
}

export function isGcpCredentialKvPathRequired(
  values: CredentialFormValidationValues,
): boolean {
  const authMode = (values.gcpAuthMode || "SERVICE_ACCOUNT_KEY") as GcpAuthMode;
  return authMode === "SERVICE_ACCOUNT_KEY";
}

export function validateGcpCredentialFields(
  values: CredentialFormValidationValues,
  context: SchemaRefinementContext,
): void {
  const authMode = (values.gcpAuthMode || "SERVICE_ACCOUNT_KEY") as GcpAuthMode;

  if (!z.enum(GCP_AUTH_MODES).safeParse(authMode).success) {
    context.addIssue({
      code: "custom",
      path: ["gcpAuthMode"],
      message: "Select a valid GCP auth mode",
    });
    return;
  }

  const provider = (values.provider || "").trim().toUpperCase();
  if (provider === "GCP_CERT_MANAGER") {
    const result = gcpCertManagerCredentialConfigSchema.safeParse({
      authMode,
      projectId: values.gcpProjectId,
      location: values.gcpLocation,
      impersonateServiceAccount: values.gcpImpersonateServiceAccount,
      certificateMap: values.gcpCertManagerCertificateMap,
    });

    if (!result.success) {
      for (const issue of result.error.issues) {
        const key = String(issue.path[0] || "");
        const fieldMap: Record<string, keyof CredentialFormValidationValues> = {
          projectId: "gcpProjectId",
          location: "gcpLocation",
          certificateMap: "gcpCertManagerCertificateMap",
        };
        const mapped = fieldMap[key];
        if (mapped) {
          context.addIssue({
            code: "custom",
            path: [mapped],
            message: issue.message,
          });
        }
      }
    }
    return;
  }

  if (provider === "GCP_PROXY_NLB") {
    const result = gcpProxyCredentialConfigSchema.safeParse({
      authMode,
      projectId: values.gcpProjectId,
      location: values.gcpLocation,
      impersonateServiceAccount: values.gcpImpersonateServiceAccount,
      targetSslProxy: values.gcpProxyTargetSslProxy,
    });
    if (!result.success) {
      for (const issue of result.error.issues) {
        const key = String(issue.path[0] || "");
        const fieldMap: Record<string, keyof CredentialFormValidationValues> = {
          projectId: "gcpProjectId",
          location: "gcpLocation",
          targetProxy: "gcpProxyTargetSslProxy",
          targetSslProxy: "gcpProxyTargetSslProxy",
        };
        const mapped = fieldMap[key];
        if (mapped) {
          context.addIssue({
            code: "custom",
            path: [mapped],
            message: issue.message,
          });
        }
      }
    }
    return;
  }

  if (
    provider === "GCP_ALB" ||
    provider === "GCP_API_GW" ||
    provider === "GCP_CLOUD_CDN"
  ) {
    const result = gcpProxyCredentialConfigSchema.safeParse({
      authMode,
      projectId: values.gcpProjectId,
      location: values.gcpLocation,
      impersonateServiceAccount: values.gcpImpersonateServiceAccount,
      targetProxy: values.gcpProxyTargetHttpsProxy,
    });
    if (!result.success) {
      for (const issue of result.error.issues) {
        const key = String(issue.path[0] || "");
        const fieldMap: Record<string, keyof CredentialFormValidationValues> = {
          projectId: "gcpProjectId",
          location: "gcpLocation",
          targetProxy: "gcpProxyTargetHttpsProxy",
          targetSslProxy: "gcpProxyTargetHttpsProxy",
        };
        const mapped = fieldMap[key];
        if (mapped) {
          context.addIssue({
            code: "custom",
            path: [mapped],
            message: issue.message,
          });
        }
      }
    }
  }
}
