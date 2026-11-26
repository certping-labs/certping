// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";

import { VendorMark } from "@/components/machine-identity/vendor-mark";
import {
  PROVIDER_LOGOS,
  providerLabel,
} from "@/lib/machine-identity/backend-display";
import type { IotProvider } from "@/types/machine-identity-backend";

interface ProviderLabelProps {
  /** Free string on the wire - the schema allows values beyond the known `IotProvider` set. */
  provider: string;
  size?: number;
  className?: string;
}

/** Device-source platform identity: vendor mark plus name. */
export function ProviderLabel({
  provider,
  size,
  className,
}: ProviderLabelProps) {
  return (
    <VendorMark
      logo={PROVIDER_LOGOS[provider as IotProvider]}
      label={providerLabel(provider)}
      height={size}
      className={className}
    />
  );
}

/**
 * The vendor mark alone - for rows that already show a provider-specific name
 * (e.g. a source's own display name) and only need a "which vendor" cue beside
 * it. Renders nothing when we have no art, so callers can place it inline
 * without a fallback.
 */
export function ProviderIcon({
  provider,
  size = 14,
  className,
}: ProviderLabelProps) {
  return (
    <VendorMark
      logo={PROVIDER_LOGOS[provider as IotProvider]}
      label={providerLabel(provider)}
      height={size}
      markOnly
      className={className}
    />
  );
}
