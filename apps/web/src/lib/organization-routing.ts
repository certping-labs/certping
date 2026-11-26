// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { Organization } from "@/types/auth";

export const getOrganizationSlug = (organization: Organization): string => {
  const explicitSlug = organization.slug?.trim();
  if (explicitSlug) {
    return explicitSlug;
  }
  throw new Error(`Organization slug is required for ${organization.name}`);
};

export const getOrganizationDetailHref = (organization: Organization): string =>
  `/settings/organizations/${encodeURIComponent(getOrganizationSlug(organization))}`;
