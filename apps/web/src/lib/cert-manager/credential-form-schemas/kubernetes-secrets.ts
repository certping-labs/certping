// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  KUBERNETES_ALL_NAMESPACES,
  KUBERNETES_SECRETS_PROVIDER,
  kubernetesCredentialConfigSchema,
  parseCredentialNamespacesInput,
} from "@/lib/credential-config-schemas/kubernetes-secrets";
import type {
  CredentialFormValidationValues,
  SchemaRefinementContext,
} from "@/lib/cert-manager/credential-form-schemas/types";

export function isKubernetesCredentialProvider(provider?: string): boolean {
  return provider === KUBERNETES_SECRETS_PROVIDER;
}

export function isKubernetesCredentialKvPathRequired(
  values: CredentialFormValidationValues,
): boolean {
  return values.k8sAuthMethod !== "SA_INCLUSTER";
}

export function validateKubernetesCredentialFields(
  values: CredentialFormValidationValues,
  context: SchemaRefinementContext,
): void {
  const namespacesInput =
    values.k8sNamespaceMode === "all_namespaces"
      ? KUBERNETES_ALL_NAMESPACES
      : (values.k8sNamespaces ?? []);

  const result = kubernetesCredentialConfigSchema.safeParse({
    authMethod: values.k8sAuthMethod,
    clusterName: values.k8sClusterName,
    namespaces: parseCredentialNamespacesInput(namespacesInput),
  });

  if (!result.success) {
    for (const issue of result.error.issues) {
      if (issue.path[0] === "clusterName") {
        context.addIssue({
          code: "custom",
          path: ["k8sClusterName"],
          message: issue.message,
        });
      } else if (issue.path[0] === "namespaces") {
        context.addIssue({
          code: "custom",
          path:
            values.k8sNamespaceMode === "all_namespaces"
              ? ["k8sNamespaceMode"]
              : ["k8sNamespaces"],
          message: issue.message,
        });
      }
    }
  }
}
