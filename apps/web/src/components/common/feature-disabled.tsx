// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import Link from "next/link";
import { LockSimpleIcon } from "@phosphor-icons/react";

import { FeatureStatePanel } from "@/components/common/feature-state-panel";
import { Button } from "@/components/ui/button";
import {
  FEATURE_DISABLED_BODY,
  featureDisabledTitle,
} from "@/lib/feature-disabled-copy";
import { featureFlagLabel } from "@/lib/feature-flags";

export { FEATURE_DISABLED_BODY };

interface FeatureDisabledPageProps {
  /** Flag key that is off; the product name comes from `featureFlagLabel`. */
  featureKey: string | undefined;
  /**
   * `page` fills the workspace (a route the user reached by URL). `inline`
   * replaces one region of a page, e.g. a panel whose request answered 423.
   */
  variant?: "page" | "inline";
  className?: string;
}

/**
 * The one "this feature is off" surface: route gate, 423 states, and any
 * panel whose feature is off all render it, so the wording never drifts. It
 * names no setting to change, because the feature may be off platform-wide
 * where an org admin cannot switch it; the body tells the user to ask their
 * CertPing administrator.
 */
export function FeatureDisabledPage({
  featureKey,
  variant = "page",
  className,
}: FeatureDisabledPageProps) {
  const featureLabel = featureFlagLabel(featureKey);

  return (
    <FeatureStatePanel
      variant={variant}
      className={className}
      icon={<LockSimpleIcon className="size-5" />}
      title={featureDisabledTitle(featureLabel)}
      body={FEATURE_DISABLED_BODY}
      actions={
        variant === "page" ? (
          <Button asChild variant="outline">
            <Link href="/dashboard">Back to dashboard</Link>
          </Button>
        ) : undefined
      }
    />
  );
}
