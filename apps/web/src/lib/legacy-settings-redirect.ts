// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Where a bookmarked settings page goes now that the organization, members,
 * account and notification pages are tabs of one page. Query parameters
 * (such as `changePassword=true`) travel with the redirect.
 */
export function legacySettingsRedirect(
  tab: "organization" | "members" | "account" | "notifications",
  searchParams?: Record<string, string | string[] | undefined>,
): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(searchParams ?? {})) {
    if (key === "tab" || value === undefined) continue;
    for (const item of Array.isArray(value) ? value : [value]) {
      params.append(key, item);
    }
  }
  params.set("tab", tab);
  return `/settings/organization-access?${params.toString()}`;
}
