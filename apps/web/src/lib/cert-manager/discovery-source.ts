// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Derives a human-readable source location from a discovered certificate's resourceId,
 * so the discovery "Source" column can show *which* account/vault a cert came from -
 * not just the provider. Purely derived from the resourceId (no backend lookup), and
 * unambiguous because a cert physically lives in exactly one account/vault.
 *
 * Returns null when nothing useful can be parsed.
 *
 *   AWS ACM ARN  arn:aws:acm:<region>:<account>:certificate/<id>  → "<account> · <region>"
 *   Azure KV id  https://<vault>.vault.azure.net/certificates/...  → "<vault>"
 */
export function getDiscoverySourceDetail(
  resourceId: string | null | undefined,
): string | null {
  if (!resourceId) {
    return null;
  }

  // AWS ARN: arn:partition:service:region:account-id:resource
  if (resourceId.startsWith("arn:")) {
    const parts = resourceId.split(":");
    const region = parts[3]?.trim() || "";
    const account = parts[4]?.trim() || "";
    if (account && region) {
      return `${account} · ${region}`;
    }
    return account || region || null;
  }

  // Azure Key Vault URL: https://<vault>.vault.azure.net/certificates/<name>/<version>
  if (resourceId.startsWith("https://")) {
    try {
      const vault = new URL(resourceId).hostname.split(".")[0]?.trim();
      return vault || null;
    } catch {
      return null;
    }
  }

  return null;
}
