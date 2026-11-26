// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  cloudflareEdgeCredentialConfigSchema,
  isCloudflareEdgeProvider,
} from "@/lib/credential-config-schemas/cloudflare-edge";
import type {
  CredentialFormValidationValues,
  SchemaRefinementContext,
} from "@/lib/cert-manager/credential-form-schemas/types";

export function isCloudflareEdgeCredentialProvider(provider?: string): boolean {
  return isCloudflareEdgeProvider(provider);
}

export function isCloudflareEdgeCredentialKvPathRequired(): boolean {
  return true;
}

export function validateCloudflareEdgeCredentialFields(
  values: CredentialFormValidationValues,
  context: SchemaRefinementContext,
): void {
  const result = cloudflareEdgeCredentialConfigSchema.safeParse({
    zoneId: values.cloudflareZoneId,
  });

  if (result.success) {
    return;
  }

  for (const issue of result.error.issues) {
    const key = String(issue.path[0] || "");
    if (key === "zoneId") {
      context.addIssue({
        code: "custom",
        path: ["cloudflareZoneId"],
        message: issue.message,
      });
    }
  }
}
