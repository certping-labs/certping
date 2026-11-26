// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useAuth } from "@/hooks/use-auth";
import { useIsOrgFeatureEnabled } from "@/hooks/use-feature-flags";
import { canViewCertificates } from "@/lib/authz";
import { FEATURE_FLAGS } from "@/lib/feature-flags";

/**
 * Whether the signed-in user may download certificates at all: the org's
 * `CERTIFICATE_DOWNLOAD` flag is confirmed on and the user holds an
 * organization-scoped certificate view permission (the export endpoint is
 * organization-scoped). Each certificate's own availability is checked
 * separately.
 *
 * <p>Kept apart from the export hook so the certificate pages, which only ask
 * this question, do not bundle the export adapter and its error mapping.
 */
export function useCanDownloadCertificates(): boolean {
  const { user } = useAuth();
  const isFeatureOn = useIsOrgFeatureEnabled(
    FEATURE_FLAGS.CERTIFICATE_DOWNLOAD,
  );
  return isFeatureOn && canViewCertificates(user);
}
