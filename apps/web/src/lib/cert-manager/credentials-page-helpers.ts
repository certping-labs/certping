// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { CredentialRecord } from "@/types/ssl";
import {
  KUBERNETES_AUTH_METHODS,
  type KubernetesAuthMethod,
  getKubernetesAuthMethodLabel,
} from "@/lib/credential-config-schemas/kubernetes-secrets";
import {
  editCredentialFormSchema,
  type EditCredentialFormValues,
} from "@/lib/cert-manager/credential-form-schemas";

export const editCredentialSchema = editCredentialFormSchema;
export type EditCredentialValues = EditCredentialFormValues;

export const K8S_AUTH_METHOD_OPTIONS: Array<{
  value: KubernetesAuthMethod;
  label: string;
}> = KUBERNETES_AUTH_METHODS.map((value) => ({
  value,
  label: getKubernetesAuthMethodLabel(value),
}));

export async function copyTextToClipboard(value: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    // Ignore copy failures silently.
  }
}

export function getCredentialTabCount(
  credentials: CredentialRecord[],
  type: "DNS" | "DEPLOYMENT",
): number {
  return credentials.filter((credential) => credential.type === type).length;
}
