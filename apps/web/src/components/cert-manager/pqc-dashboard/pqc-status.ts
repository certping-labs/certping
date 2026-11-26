// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { QuantumStatus } from "@/types/cbom-pqc";

export const PQC_STATUS_COPY: Record<
  QuantumStatus,
  {
    label: string;
    variant: "destructive" | "secondary" | "success" | "warning";
  }
> = {
  DEPRECATED_2030: { label: "Deprecated 2030", variant: "warning" },
  DISALLOWED_2035: { label: "Disallowed 2035", variant: "destructive" },
  PQC_COMPLIANT: { label: "PQC compliant", variant: "success" },
  UNKNOWN: { label: "Unknown", variant: "secondary" },
};

export const PQC_STATUS_COLOR: Record<QuantumStatus, string> = {
  DEPRECATED_2030: "bg-warning",
  DISALLOWED_2035: "bg-danger",
  PQC_COMPLIANT: "bg-success",
  UNKNOWN: "bg-muted-foreground",
};
