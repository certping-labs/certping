// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import {
  WarningIcon,
  QuestionIcon,
  ShieldCheckIcon,
  SirenIcon,
} from "@phosphor-icons/react/dist/ssr";
import type { Icon as PhosphorIcon } from "@phosphor-icons/react";

import { Card } from "@/components/ui/card";
import type { PqcReadinessSummary, QuantumStatus } from "@/types/cbom-pqc";
import { TopActionTile } from "./top-action-tile";
import type { TopActionTone } from "./top-action-tile";

interface TopActionsCardProps {
  onReviewStatus: (status: QuantumStatus) => void;
  summary?: PqcReadinessSummary;
}

interface TopActionDefinition {
  description: string;
  icon: PhosphorIcon;
  label: string;
  status: QuantumStatus;
  tone: TopActionTone;
  value: number;
}

export function TopActionsCard({
  onReviewStatus,
  summary,
}: TopActionsCardProps) {
  const actions = buildTopActions(summary);

  return (
    <Card className="overflow-hidden">
      <header className="flex flex-col gap-1 px-4 py-4 sm:px-5">
        <h2 className="text-sm font-semibold">Top remediation actions</h2>
        <p className="text-xs text-muted-foreground">
          Select a priority to filter the certificate inventory.
        </p>
      </header>
      <div className="grid gap-px border-t bg-border sm:grid-cols-2 xl:grid-cols-4">
        {actions.map((action) => (
          <TopActionTile
            key={action.status}
            {...action}
            onClick={() => onReviewStatus(action.status)}
          />
        ))}
      </div>
    </Card>
  );
}

function buildTopActions(
  summary?: PqcReadinessSummary,
): readonly TopActionDefinition[] {
  return [
    {
      description: "Algorithms blocked by the 2035 milestone",
      icon: SirenIcon,
      label: "Review 2035 disallow queue",
      status: "DISALLOWED_2035",
      tone: "danger",
      value: summary?.disallowed2035 ?? 0,
    },
    {
      description: "Migration required before the 2030 milestone",
      icon: WarningIcon,
      label: "Plan 2030 migrations",
      status: "DEPRECATED_2030",
      tone: "warning",
      value: summary?.deprecated2030 ?? 0,
    },
    {
      description: "Public-key metadata needs classification",
      icon: QuestionIcon,
      label: "Classify unknown algorithms",
      status: "UNKNOWN",
      tone: "neutral",
      value: summary?.unknown ?? 0,
    },
    {
      description: "Certificates already aligned to PQC standards",
      icon: ShieldCheckIcon,
      label: "Review PQC-ready inventory",
      status: "PQC_COMPLIANT",
      tone: "success",
      value: summary?.pqcCompliant ?? 0,
    },
  ];
}
