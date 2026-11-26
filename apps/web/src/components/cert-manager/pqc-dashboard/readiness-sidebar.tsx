// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";

import type { PqcReadinessSummary } from "@/types/cbom-pqc";
import { AlgorithmStatusCard } from "./algorithm-status-card";
import { TransitionMilestonesCard } from "./transition-milestones-card";

interface ReadinessSidebarProps {
  summary?: PqcReadinessSummary;
}

export function ReadinessSidebar({ summary }: ReadinessSidebarProps) {
  return (
    <aside className="space-y-3" aria-label="PQC readiness details">
      <AlgorithmStatusCard summary={summary} />
      <TransitionMilestonesCard />
    </aside>
  );
}
