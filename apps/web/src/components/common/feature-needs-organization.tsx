// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import Link from "next/link";
import { BuildingsIcon } from "@phosphor-icons/react";

import { FeatureStatePanel } from "@/components/common/feature-state-panel";
import { Button } from "@/components/ui/button";
import { getDefaultAuthorizedRoute } from "@/lib/app-routes";
import { featureFlagLabel } from "@/lib/feature-flags";
import { useAuthStore } from "@/stores/auth-store";

/**
 * Shown instead of a page whose data lives inside one organization, to a
 * session that has none (a platform super admin). The app has no way to
 * switch organization, so the only path is signing in to one.
 */
export function FeatureNeedsOrganizationPage({
  featureKey,
}: {
  featureKey: string | undefined;
}) {
  const homeHref = useAuthStore((state) =>
    getDefaultAuthorizedRoute(state.user, Boolean(state.isSuperAdmin)),
  );
  const featureLabel = featureFlagLabel(featureKey);

  return (
    <FeatureStatePanel
      icon={<BuildingsIcon className="size-5" />}
      title={<>{featureLabel} works inside an organization</>}
      body="Sign in to an organization to use it."
      actions={
        <Button asChild variant="outline">
          <Link href={homeHref}>Go to your home page</Link>
        </Button>
      }
    />
  );
}
