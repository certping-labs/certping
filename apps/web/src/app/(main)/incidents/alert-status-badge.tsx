// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";

import { Badge, type BadgeProps } from "@/components/ui/badge";
import { humanizeEnum } from "@/lib/humanize";

const getAlertStatusVariant = (status: string): BadgeProps["variant"] => {
  const normalized = status.toLowerCase();
  if (
    normalized.includes("success") ||
    normalized.includes("resolved") ||
    normalized.includes("issued") ||
    normalized.includes("active") ||
    normalized.includes("delivered")
  ) {
    return "success";
  }
  if (
    normalized.includes("fail") ||
    normalized.includes("error") ||
    normalized.includes("invalid")
  ) {
    return "destructive";
  }
  if (
    normalized.includes("pending") ||
    normalized.includes("processing") ||
    normalized.includes("open")
  ) {
    return "warning";
  }
  return "secondary";
};

interface AlertStatusBadgeProps {
  status: string;
  className?: string;
}

export function AlertStatusBadge({ status, className }: AlertStatusBadgeProps) {
  return (
    <Badge
      variant={getAlertStatusVariant(status)}
      textOnly
      className={className}
    >
      {humanizeEnum(status)}
    </Badge>
  );
}
