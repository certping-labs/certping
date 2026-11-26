// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";

interface MetricPairProps {
  label: string;
  /** Plain text value; truncated on overflow. */
  value?: string;
  /** Rendered instead of {@link value} when the cell needs markup. */
  node?: React.ReactNode;
}

/** One label/value pair in a connector or source summary row. */
export function MetricPair({ label, value, node }: MetricPairProps) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-sm">
        {node ?? <span className="block truncate">{value}</span>}
      </dd>
    </div>
  );
}
