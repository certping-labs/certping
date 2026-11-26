// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";

import { VendorMark } from "@/components/machine-identity/vendor-mark";
import {
  CA_PROVIDER_LOGOS,
  caProviderLabel,
} from "@/lib/machine-identity/backend-display";

interface CaConnectorLabelProps {
  /** Free string on the wire, e.g. "EJBCA" / "SMALLSTEP". */
  caProvider: string;
  size?: number;
  markOnly?: boolean;
  className?: string;
}

/** Certificate-authority identity: vendor mark plus name. */
export function CaConnectorLabel({
  caProvider,
  size,
  markOnly,
  className,
}: CaConnectorLabelProps) {
  return (
    <VendorMark
      logo={CA_PROVIDER_LOGOS[caProvider]}
      label={caProviderLabel(caProvider)}
      height={size}
      markOnly={markOnly}
      className={className}
    />
  );
}
